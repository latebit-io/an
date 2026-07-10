package utils

import (
	"crypto/subtle"
	"errors"
	"regexp"

	"github.com/google/uuid"
)

var (
	keyRegex   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// ValidateKey validates identifier keys (tenants, resource types, actions,
// roles, subjects, condition sets): lowercase alphanumeric start, then
// lowercase alphanumeric, underscore or hyphen, max 64 characters.
func ValidateKey(key string) error {
	if !keyRegex.MatchString(key) {
		return errors.New("invalid key: must match ^[a-z0-9][a-z0-9_-]{0,63}$")
	}
	return nil
}

func ValidateEmail(email string) error {
	if len(email) > 254 {
		return errors.New("email too long")
	}
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

// ValidateUUID validates a uuid identifier.
func ValidateUUID(id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.New("invalid uuid")
	}
	return nil
}

// SafeCompare compares strings avoiding timing attacks
func SafeCompare(string1, string2 string) bool {
	return subtle.ConstantTimeCompare([]byte(string1), []byte(string2)) == 1
}
