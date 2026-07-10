package apikeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/latebit-io/an/internal/utils"
)

// Token shape: ank_<64 hex chars>. The first 8 hex chars after the marker
// are the public prefix used for lookup; only the sha256 of the full token
// is stored.
const (
	tokenMarker  = "ank_"
	prefixLength = len(tokenMarker) + 8
)

// ApiKey is a tenant-scoped credential. A key can manage and check only its
// own tenant (permit.io environment-key model). The secret exists solely in
// the create response.
type ApiKey struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenantId"`
	Name     string    `json:"name"`
	Prefix   string    `json:"prefix"`
	Created  time.Time `json:"created"`
}

// CreatedApiKey carries the one-time secret alongside the stored key.
type CreatedApiKey struct {
	ApiKey
	Key string `json:"key"`
}

type ApiKeyService interface {
	Create(ctx context.Context, tenantID, name string) (*CreatedApiKey, error)
	List(ctx context.Context, tenantID string) ([]ApiKey, error)
	Revoke(ctx context.Context, tenantID, id string) error
	// Authenticate resolves a presented token to its tenant.
	Authenticate(ctx context.Context, token string) (string, error)
}

type DefaultApiKeyService struct {
	repo ApiKeyRepository
}

func NewDefaultApiKeyService(repo ApiKeyRepository) ApiKeyService {
	return &DefaultApiKeyService{repo: repo}
}

// Create mints a tenant-scoped key. The returned secret is shown once and
// never stored — only its hash and lookup prefix are.
func (s *DefaultApiKeyService) Create(ctx context.Context, tenantID, name string) (*CreatedApiKey, error) {
	if name == "" {
		return nil, InvalidApiKeyRequestError{Value: "name is required"}
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	token := tokenMarker + hex.EncodeToString(secret)

	key := ApiKey{
		TenantID: tenantID,
		Name:     name,
		Prefix:   token[:prefixLength],
	}
	created, err := s.repo.Create(ctx, key, hashToken(token))
	if err != nil {
		return nil, err
	}
	return &CreatedApiKey{ApiKey: *created, Key: token}, nil
}

func (s *DefaultApiKeyService) List(ctx context.Context, tenantID string) ([]ApiKey, error) {
	return s.repo.ReadAll(ctx, tenantID)
}

func (s *DefaultApiKeyService) Revoke(ctx context.Context, tenantID, id string) error {
	if err := utils.ValidateUUID(id); err != nil {
		return InvalidApiKeyRequestError{Value: "invalid api key id"}
	}
	return s.repo.Delete(ctx, tenantID, id)
}

// Authenticate looks the token up by prefix and compares hashes in constant
// time. High-entropy random tokens make sha256 the right hash here — key
// authentication runs on every request.
func (s *DefaultApiKeyService) Authenticate(ctx context.Context, token string) (string, error) {
	if !strings.HasPrefix(token, tokenMarker) || len(token) < prefixLength {
		return "", InvalidApiKeyError{}
	}
	tenantID, storedHash, err := s.repo.ReadByPrefix(ctx, token[:prefixLength])
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(hashToken(token))) != 1 {
		return "", InvalidApiKeyError{}
	}
	return tenantID, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}
