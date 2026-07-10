package social

import (
	"context"
	"errors"

	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/authn"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/latebit-io/an/internal/utils"
)

// Identity is what a provider asserts about the user after validating an
// ID token.
type Identity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}

// Validator verifies a provider's ID token; one per configured provider.
type Validator interface {
	Name() string
	Validate(ctx context.Context, idToken string) (*Identity, error)
}

type SocialService interface {
	AddValidator(validator Validator)
	Authenticate(ctx context.Context, tenantID, provider, idToken, clientID string) (*authn.Authenticated, error)
}

type DefaultSocialService struct {
	validators   map[string]Validator
	accounts     accounts.AccountRepository
	links        SocialRepository
	tokenizer    tokens.Tokenizer
	txManager    utils.TxManager
	passwordCost int
}

func NewDefaultSocialService(accountRepository accounts.AccountRepository, links SocialRepository,
	tokenizer tokens.Tokenizer, txManager utils.TxManager, passwordCost int) SocialService {
	return &DefaultSocialService{
		validators:   make(map[string]Validator),
		accounts:     accountRepository,
		links:        links,
		tokenizer:    tokenizer,
		txManager:    txManager,
		passwordCost: passwordCost,
	}
}

func (s *DefaultSocialService) AddValidator(validator Validator) {
	s.validators[validator.Name()] = validator
}

// Authenticate validates the provider ID token and logs the user on,
// creating the account on first sight. Social accounts are born verified:
// the provider already asserted the email (EmailVerified is required).
func (s *DefaultSocialService) Authenticate(ctx context.Context, tenantID, provider, idToken,
	clientID string) (*authn.Authenticated, error) {
	validator, ok := s.validators[provider]
	if !ok {
		return nil, ProviderNotConfiguredError{Value: provider}
	}
	identity, err := validator.Validate(ctx, idToken)
	if err != nil {
		return nil, err
	}
	if identity.Email == "" {
		return nil, SocialTokenInvalidError{Value: "no email in ID token"}
	}
	if !identity.EmailVerified {
		return nil, EmailNotVerifiedError{Value: identity.Email}
	}

	// One transaction: a failed Link must not leave behind a freshly
	// created (or freshly verified) account without its social identity.
	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		account, err := s.findOrCreate(ctx, tenantID, identity.Email)
		if err != nil {
			return err
		}
		if account.Deleted {
			return authn.AuthenticationError{}
		}
		if !account.Enabled {
			return accounts.AccountDisabledError{Value: identity.Email}
		}
		if !account.Verified {
			if err := s.accounts.SetVerified(ctx, tenantID, identity.Email); err != nil {
				return err
			}
		}
		return s.links.Link(ctx, account.ID, identity.Provider, identity.Subject)
	})
	if err != nil {
		return nil, err
	}

	accessToken, _, err := s.tokenizer.CreateAccessToken(ctx, tenantID, identity.Email, clientID)
	if err != nil {
		return nil, err
	}
	refreshToken, _, err := s.tokenizer.CreateRefreshToken(ctx, tenantID, identity.Email, clientID)
	if err != nil {
		return nil, err
	}
	return &authn.Authenticated{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// findOrCreate reads the account or creates it born verified with an
// unusable random password (password logon stays possible only after a
// reset).
func (s *DefaultSocialService) findOrCreate(ctx context.Context, tenantID,
	email string) (*accounts.Account, error) {
	account, err := s.accounts.Read(ctx, tenantID, email)
	if err == nil {
		return account, nil
	}
	var notFound accounts.AccountNotFoundError
	if !errors.As(err, &notFound) {
		return nil, err
	}
	randomPassword, err := utils.RandomToken()
	if err != nil {
		return nil, err
	}
	passwordHash, err := utils.BcryptHash(randomPassword, s.passwordCost)
	if err != nil {
		return nil, err
	}
	return s.accounts.CreateVerified(ctx, accounts.Account{
		TenantID:     tenantID,
		Email:        email,
		PasswordHash: passwordHash,
	})
}
