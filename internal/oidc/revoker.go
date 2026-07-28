package oidc

import "context"

// SessionRevoker ends everything the OIDC surface holds for one account:
// the single sign-on browser sessions, the issued grants, and any
// authorization request already tied to the account.
//
// It exists so the accounts service can revoke on this surface the way it
// already does on the api-key one. The two surfaces key sessions
// differently (email there, account id here), so the translation happens in
// the statements rather than in the caller.
type SessionRevoker struct {
	sessions BrowserSessionRepository
	tokens   TokenRepository
}

func NewSessionRevoker(sessions BrowserSessionRepository,
	tokenRepository TokenRepository) *SessionRevoker {
	return &SessionRevoker{sessions: sessions, tokens: tokenRepository}
}

// DeleteAll matches the shape the accounts service revokes through.
func (r *SessionRevoker) DeleteAll(ctx context.Context, tenantID, email string) error {
	if err := r.sessions.DeleteAllForEmail(ctx, tenantID, email); err != nil {
		return err
	}
	return r.tokens.DeleteGrantsForEmail(ctx, tenantID, email)
}
