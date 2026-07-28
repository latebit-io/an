package oidc

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/authn"
	internaloidc "github.com/latebit-io/an/internal/oidc"
	"github.com/latebit-io/an/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/op"
)

//go:embed templates/*.html
var templateFiles embed.FS

// Cookie names. The session cookie is the single sign-on session; the csrf
// cookie is the double-submit token guarding the login form.
const (
	SessionCookieName = "an_session"
	CSRFCookieName    = "an_login_csrf"
)

// amrPassword marks how the user authenticated, carried into the id_token.
var amrPassword = []string{"pwd"}

type LoginHandler struct {
	storage        *internaloidc.Storage
	sessions       internaloidc.BrowserSessionRepository
	authentication authn.AuthenticationService
	accounts       accounts.AccountRepository
	clients        internaloidc.ClientRegistry
	provider       *op.Provider
	publicBaseURL  string
	secureCookies  bool
	sessionExpiry  time.Duration
	templates      *template.Template
}

func NewLoginHandler(storage *internaloidc.Storage,
	sessions internaloidc.BrowserSessionRepository, authentication authn.AuthenticationService,
	accountRepository accounts.AccountRepository, clients internaloidc.ClientRegistry,
	provider *op.Provider, publicBaseURL string, secureCookies bool,
	sessionExpiry time.Duration) (LoginHandler, error) {
	templates, err := template.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		return LoginHandler{}, err
	}
	return LoginHandler{
		storage:        storage,
		sessions:       sessions,
		authentication: authentication,
		accounts:       accountRepository,
		clients:        clients,
		provider:       provider,
		publicBaseURL:  publicBaseURL,
		secureCookies:  secureCookies,
		sessionExpiry:  sessionExpiry,
		templates:      templates,
	}, nil
}

type loginPage struct {
	Action        string
	AuthRequestID string
	CSRF          string
	Email         string
	Error         string
}

// Login renders the sign-in form, or completes the authorization request
// straight away when a live single sign-on session already covers it. That
// second path is what makes the second app silent.
func (h LoginHandler) Login(c *echo.Context) error {
	tenantID := c.Param("tenantId")
	authRequestID := c.QueryParam("authRequestId")
	if tenantID == "" || authRequestID == "" {
		return c.String(http.StatusBadRequest, "missing tenant or authorization request")
	}
	ctx := internaloidc.WithTenant(c.Request().Context(), tenantID)

	if session := h.liveSession(ctx, c, tenantID); session != nil {
		return h.complete(ctx, c, tenantID, authRequestID, session.AccountID, session.AuthTime)
	}

	csrf, err := utils.RandomToken()
	if err != nil {
		return c.String(http.StatusInternalServerError, "could not start login")
	}
	c.SetCookie(sessionCookie(CSRFCookieName, csrf, h.secureCookies, time.Now().Add(time.Hour)))
	return h.render(c, http.StatusOK, tenantID, authRequestID, csrf, "", "")
}

// Submit authenticates the credentials. It is the only place in the system
// where a password is entered under the OIDC flow, which is the point of
// the whole surface.
func (h LoginHandler) Submit(c *echo.Context) error {
	tenantID := c.Param("tenantId")
	authRequestID := c.FormValue("authRequestId")
	email := c.FormValue("email")
	password := c.FormValue("password")
	ctx := internaloidc.WithTenant(c.Request().Context(), tenantID)

	csrf, err := c.Request().Cookie(CSRFCookieName)
	if err != nil || csrf.Value == "" || !utils.SafeCompare(csrf.Value, c.FormValue("csrf")) {
		// Re-issue the token as well as the form. Rendering the failure
		// with an empty one would make every retry fail the same check,
		// which reads to the user as a login that simply does not work.
		fresh, tokenErr := utils.RandomToken()
		if tokenErr != nil {
			return c.String(http.StatusInternalServerError, "could not start login")
		}
		c.SetCookie(sessionCookie(CSRFCookieName, fresh, h.secureCookies, time.Now().Add(time.Hour)))
		return h.render(c, http.StatusBadRequest, tenantID, authRequestID, fresh, email,
			"Your sign-in session expired. Try again.")
	}

	account, err := h.authentication.VerifyPassword(ctx, tenantID, email, password)
	if err != nil {
		// Wrong password, unknown account, unverified, disabled and locked
		// out all render the same way: the form must not be an oracle.
		return h.render(c, http.StatusUnauthorized, tenantID, authRequestID, csrf.Value, email,
			loginErrorMessage(err))
	}

	authTime := time.Now()
	session, plaintext, err := h.sessions.Create(ctx, internaloidc.BrowserSession{
		TenantID:  tenantID,
		AccountID: account.ID,
		AuthTime:  authTime,
		Expires:   authTime.Add(h.sessionExpiry),
	})
	if err != nil {
		return c.String(http.StatusInternalServerError, "could not start session")
	}
	c.SetCookie(sessionCookie(SessionCookieName, plaintext, h.secureCookies, session.Expires))
	// The csrf token is spent.
	c.SetCookie(sessionCookie(CSRFCookieName, "", h.secureCookies, time.Unix(0, 0)))

	return h.complete(ctx, c, tenantID, authRequestID, account.ID, authTime)
}

// Logout ends the single sign-on session. Without it a user has a session
// they cannot terminate, which is why RP-initiated logout is in the first
// cut rather than deferred with the rest of the logout story.
//
// It is mounted at the path discovery advertises as end_session_endpoint,
// because an endpoint a client is told to call has to be the one that
// answers.
func (h LoginHandler) Logout(c *echo.Context) error {
	tenantID := c.Param("tenantId")
	ctx := internaloidc.WithTenant(c.Request().Context(), tenantID)

	if cookie, err := c.Request().Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		// Read before deleting: the grants are keyed by subject, and the
		// session is the only thing that knows which subject this is.
		session, readErr := h.sessions.Read(ctx, tenantID, cookie.Value)
		if err := h.sessions.Delete(ctx, tenantID, cookie.Value); err != nil &&
			!errors.As(err, &internaloidc.BrowserSessionNotFoundError{}) {
			return c.String(http.StatusInternalServerError, "could not end session")
		}
		// Ending the browser session alone would leave every issued token
		// live until it expired, so signing out would not sign anything out.
		if readErr == nil {
			clientID := c.QueryParam("client_id")
			if err := h.storage.TerminateSession(ctx, session.AccountID, clientID); err != nil {
				return c.String(http.StatusInternalServerError, "could not end session")
			}
		}
	}
	c.SetCookie(sessionCookie(SessionCookieName, "", h.secureCookies, time.Unix(0, 0)))

	redirect := c.QueryParam("post_logout_redirect_uri")
	if redirect == "" {
		return c.String(http.StatusOK, "Signed out.")
	}
	// Only where the client registered. Redirecting anywhere the caller
	// names would hand a phisher a link that genuinely starts at the
	// identity provider.
	err := h.clients.PostLogoutRedirect(ctx, tenantID, c.QueryParam("client_id"), redirect)
	if err != nil {
		return c.String(http.StatusBadRequest, "redirect uri not allowed")
	}
	target, err := url.Parse(redirect)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid redirect")
	}
	// state round trips so the client can match the response to its
	// request, as it does at /authorize.
	if state := c.QueryParam("state"); state != "" {
		query := target.Query()
		query.Set("state", state)
		target.RawQuery = query.Encode()
	}
	return c.Redirect(http.StatusFound, target.String())
}

// complete marks the authorization request authenticated and hands control
// back to the library, which mints the code and redirects to the client.
func (h LoginHandler) complete(ctx context.Context, c *echo.Context, tenantID, authRequestID,
	accountID string, authTime time.Time) error {
	err := h.storage.AuthenticateRequest(ctx, authRequestID, accountID, authTime, amrPassword)
	if err != nil {
		return c.String(http.StatusBadRequest, "unknown or expired authorization request")
	}
	issuerCtx := op.ContextWithIssuer(ctx, Issuer(h.publicBaseURL, tenantID))
	return c.Redirect(http.StatusFound, op.AuthCallbackURL(h.provider)(issuerCtx, authRequestID))
}

// liveSession resolves the single sign-on cookie, if any.
func (h LoginHandler) liveSession(ctx context.Context, c *echo.Context,
	tenantID string) *internaloidc.BrowserSession {
	cookie, err := c.Request().Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	session, err := h.sessions.Read(ctx, tenantID, cookie.Value)
	if err != nil {
		return nil
	}
	// A session outlives the account it belongs to only until the next
	// check: deleted and disabled accounts must not sign in silently.
	account, err := h.accounts.ReadByID(ctx, tenantID, session.AccountID)
	if err != nil || account.Deleted || !account.Enabled {
		return nil
	}
	return session
}

func (h LoginHandler) render(c *echo.Context, status int, tenantID, authRequestID, csrf, email,
	message string) error {
	page := loginPage{
		Action:        Issuer(h.publicBaseURL, tenantID) + LoginPath,
		AuthRequestID: authRequestID,
		CSRF:          csrf,
		Email:         email,
		Error:         message,
	}
	c.Response().Header().Set(echo.HeaderContentSecurityPolicy,
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
	c.Response().WriteHeader(status)
	return h.templates.ExecuteTemplate(c.Response(), "login", page)
}

// loginErrorMessage keeps the form from telling an attacker which accounts
// exist. Only lockout is distinguished, because a user who cannot get in
// needs to know why.
func loginErrorMessage(err error) string {
	if errors.As(err, &authn.AccountLockedError{}) {
		return "Too many failed attempts. Try again later."
	}
	return "Incorrect email or password."
}
