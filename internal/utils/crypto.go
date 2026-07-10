package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"golang.org/x/crypto/bcrypt"
)

// BcryptHash hashes low-entropy secrets (passwords, logon codes) at the
// given cost.
func BcryptHash(value string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(value), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// BcryptVerify reports whether value matches hash; a mismatch is (false, nil),
// anything else is an error.
func BcryptVerify(hash, value string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(value))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return false, err
}

// Sha256Hex hashes high-entropy random tokens (api keys, verification and
// reset tokens) for storage at rest.
func Sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// RandomToken returns 32 random bytes hex encoded (256 bits of entropy).
func RandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// RandomDigits returns n cryptographically random decimal digits.
func RandomDigits(n int) (string, error) {
	digits := make([]byte, n)
	for i := range digits {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		digits[i] = byte('0' + d.Int64())
	}
	return string(digits), nil
}

// ValidatePassword enforces the password bounds: at least 8 characters and
// at most 72 bytes (the bcrypt input limit).
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

// ValidateCode checks a logon code is exactly size decimal digits.
func ValidateCode(code string, size int) error {
	if len(code) != size {
		return errors.New("invalid code")
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return errors.New("invalid code")
		}
	}
	return nil
}
