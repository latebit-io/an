package social

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

const googleIssuer = "https://accounts.google.com"

type GoogleValidator struct {
	verifier *oidc.IDTokenVerifier
}

type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// NewGoogleValidator verifies Google ID tokens against the OAuth client id
// using OIDC discovery (keys are fetched and cached by go-oidc).
func NewGoogleValidator(ctx context.Context, clientID string) (*GoogleValidator, error) {
	provider, err := oidc.NewProvider(ctx, googleIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create google OIDC provider: %w", err)
	}
	return &GoogleValidator{verifier: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}

func (gv *GoogleValidator) Name() string {
	return "google"
}

func (gv *GoogleValidator) Validate(ctx context.Context, idToken string) (*Identity, error) {
	token, err := gv.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, SocialTokenInvalidError{Value: err.Error()}
	}
	var claims googleClaims
	if err := token.Claims(&claims); err != nil {
		return nil, SocialTokenInvalidError{Value: err.Error()}
	}
	return &Identity{
		Provider:      gv.Name(),
		Subject:       token.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
	}, nil
}
