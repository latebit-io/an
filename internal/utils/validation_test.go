package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"simple", "document", false},
		{"with hyphen", "my-resource", false},
		{"with underscore", "my_resource", false},
		{"single char", "a", false},
		{"digit start", "1resource", false},
		{"max length", strings.Repeat("a", 64), false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 65), true},
		{"uppercase", "Document", true},
		{"leading hyphen", "-doc", true},
		{"space", "my doc", true},
		{"colon", "doc:read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid", "user@example.com", false},
		{"subdomain", "user@mail.example.com", false},
		{"plus", "user+tag@example.com", false},
		{"empty", "", true},
		{"no at", "userexample.com", true},
		{"no tld", "user@example", true},
		{"too long", strings.Repeat("a", 250) + "@x.io", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSafeCompare(t *testing.T) {
	assert.True(t, SafeCompare("secret", "secret"))
	assert.False(t, SafeCompare("secret", "other"))
	assert.False(t, SafeCompare("secret", ""))
}
