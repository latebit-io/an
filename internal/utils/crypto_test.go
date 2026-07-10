package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBcryptHashAndVerify(t *testing.T) {
	hash, err := BcryptHash("correct horse", 4)
	require.NoError(t, err)

	match, err := BcryptVerify(hash, "correct horse")
	require.NoError(t, err)
	assert.True(t, match)

	match, err = BcryptVerify(hash, "wrong horse")
	require.NoError(t, err)
	assert.False(t, match)
}

func TestSha256Hex(t *testing.T) {
	assert.Equal(t,
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		Sha256Hex("hello"))
}

func TestRandomToken(t *testing.T) {
	token, err := RandomToken()
	require.NoError(t, err)
	assert.Len(t, token, 64)

	other, err := RandomToken()
	require.NoError(t, err)
	assert.NotEqual(t, token, other)
}

func TestRandomDigits(t *testing.T) {
	code, err := RandomDigits(6)
	require.NoError(t, err)
	require.NoError(t, ValidateCode(code, 6))
}

func TestValidatePassword(t *testing.T) {
	assert.Error(t, ValidatePassword("short"))
	assert.Error(t, ValidatePassword(string(make([]byte, 73))))
	assert.NoError(t, ValidatePassword("long enough"))
}

func TestValidateCode(t *testing.T) {
	assert.NoError(t, ValidateCode("123456", 6))
	assert.Error(t, ValidateCode("12345", 6))
	assert.Error(t, ValidateCode("12345a", 6))
}
