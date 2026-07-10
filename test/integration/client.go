package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a thin typed client for the an API used by the black-box
// integration suite (seed for a future an-client library).
type Client struct {
	baseURI string
	apiKey  string
	http    *http.Client
}

// Error is an RFC 7807 problem details response.
type Error struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Status, e.Title, e.Detail)
}

func NewClient(baseURI, apiKey string) *Client {
	return &Client{baseURI: baseURI, apiKey: apiKey, http: &http.Client{Timeout: 10 * time.Second}}
}

// WithKey returns a client using a different api key against the same
// service.
func (c *Client) WithKey(apiKey string) *Client {
	return NewClient(c.baseURI, apiKey)
}

type RegisteredAccount struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenantId"`
	Email             string `json:"email"`
	Verified          bool   `json:"verified"`
	VerificationToken string `json:"verificationToken"`
}

type ResetToken struct {
	Token   string    `json:"resetToken"`
	Expires time.Time `json:"expires"`
}

type Authenticated struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type Claims struct {
	TenantID  string    `json:"tenantId"`
	ClientID  string    `json:"clientId"`
	Subject   string    `json:"subject"`
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Audience  []string  `json:"audience"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type IssuedCode struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type ApiKey struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	Name     string `json:"name"`
	Prefix   string `json:"prefix"`
	Key      string `json:"key"`
}

func (c *Client) Register(ctx context.Context, tenantID, email, password string) (*RegisteredAccount, error) {
	out := &RegisteredAccount{}
	err := c.do(ctx, http.MethodPost, "/api/accounts",
		map[string]string{"tenantId": tenantID, "email": email, "password": password}, out)
	return out, err
}

func (c *Client) Verify(ctx context.Context, tenantID, email, token string) error {
	return c.do(ctx, http.MethodPost, "/api/accounts/verify",
		map[string]string{"tenantId": tenantID, "email": email, "verificationToken": token}, nil)
}

func (c *Client) ResendVerification(ctx context.Context, tenantID, email string) (string, error) {
	out := &struct {
		VerificationToken string `json:"verificationToken"`
	}{}
	err := c.do(ctx, http.MethodPost, "/api/accounts/verify/resend",
		map[string]string{"tenantId": tenantID, "email": email}, out)
	return out.VerificationToken, err
}

func (c *Client) Forgot(ctx context.Context, tenantID, email string) (*ResetToken, error) {
	out := &ResetToken{}
	err := c.do(ctx, http.MethodPost, "/api/accounts/forgot",
		map[string]string{"tenantId": tenantID, "email": email}, out)
	return out, err
}

func (c *Client) Reset(ctx context.Context, tenantID, email, token, newPassword string) error {
	return c.do(ctx, http.MethodPost, "/api/accounts/reset",
		map[string]string{"tenantId": tenantID, "email": email, "resetToken": token,
			"newPassword": newPassword}, nil)
}

func (c *Client) UpdatePassword(ctx context.Context, tenantID, email, currentPassword,
	newPassword string) error {
	return c.do(ctx, http.MethodPut, "/api/accounts/password",
		map[string]string{"tenantId": tenantID, "email": email,
			"currentPassword": currentPassword, "newPassword": newPassword}, nil)
}

func (c *Client) DeleteAccount(ctx context.Context, tenantID, email string) error {
	return c.do(ctx, http.MethodPut, "/api/accounts/delete",
		map[string]string{"tenantId": tenantID, "email": email}, nil)
}

func (c *Client) Authenticate(ctx context.Context, tenantID, email, clientID,
	password string) (*Authenticated, error) {
	out := &Authenticated{}
	err := c.do(ctx, http.MethodPost, "/api/authenticate",
		map[string]string{"tenantId": tenantID, "email": email, "clientId": clientID,
			"password": password}, out)
	return out, err
}

func (c *Client) Acknowledge(ctx context.Context, tenantID string, tokens Authenticated) error {
	return c.do(ctx, http.MethodPost, "/api/authenticate/ack",
		map[string]string{"tenantId": tenantID, "accessToken": tokens.AccessToken,
			"refreshToken": tokens.RefreshToken}, nil)
}

func (c *Client) Renew(ctx context.Context, tenantID, refreshToken string) (*Authenticated, error) {
	out := &Authenticated{}
	err := c.do(ctx, http.MethodPost, "/api/authenticate/renew",
		map[string]string{"tenantId": tenantID, "refreshToken": refreshToken}, out)
	return out, err
}

func (c *Client) Revoke(ctx context.Context, tenantID, email, clientID string) error {
	return c.do(ctx, http.MethodPut, "/api/authenticate/revoke",
		map[string]string{"tenantId": tenantID, "email": email, "clientId": clientID}, nil)
}

func (c *Client) Validate(ctx context.Context, tenantID, accessToken string) (*Claims, error) {
	out := &Claims{}
	err := c.do(ctx, http.MethodPost, "/api/authenticate/validate",
		map[string]string{"tenantId": tenantID, "accessToken": accessToken}, out)
	return out, err
}

func (c *Client) RequestCode(ctx context.Context, tenantID, email string) (*IssuedCode, error) {
	out := &IssuedCode{}
	err := c.do(ctx, http.MethodPost, "/api/authenticate/code/request",
		map[string]string{"tenantId": tenantID, "email": email}, out)
	return out, err
}

func (c *Client) CodeLogon(ctx context.Context, tenantID, email, clientID,
	code string) (*Authenticated, error) {
	out := &Authenticated{}
	err := c.do(ctx, http.MethodPost, "/api/authenticate/code",
		map[string]string{"tenantId": tenantID, "email": email, "clientId": clientID,
			"code": code}, out)
	return out, err
}

func (c *Client) JWKS(ctx context.Context) (*JWKS, error) {
	out := &JWKS{}
	err := c.do(ctx, http.MethodGet, "/.well-known/jwks.json", nil, out)
	return out, err
}

func (c *Client) CreateApiKey(ctx context.Context, tenantID, name string) (*ApiKey, error) {
	out := &ApiKey{}
	err := c.do(ctx, http.MethodPost, "/api/apikeys",
		map[string]string{"tenantId": tenantID, "name": name}, out)
	return out, err
}

func (c *Client) DeleteApiKey(ctx context.Context, tenantID, id string) error {
	return c.do(ctx, http.MethodPut, "/api/apikeys/delete",
		map[string]string{"tenantId": tenantID, "id": id}, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURI+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		request.Header.Set("X-AN-API-KEY", c.apiKey)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		problem := &Error{Status: response.StatusCode}
		_ = json.NewDecoder(response.Body).Decode(problem)
		return problem
	}
	if out != nil && response.StatusCode != http.StatusNoContent {
		return json.NewDecoder(response.Body).Decode(out)
	}
	return nil
}
