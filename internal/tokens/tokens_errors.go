package tokens

// NoSigningKeyError signals that no signing key exists yet.
type NoSigningKeyError struct{}

func (e NoSigningKeyError) Error() string {
	return "no signing key exists"
}

// TokenInvalidError signals a JWT that failed validation: bad signature,
// expired, unknown kid, wrong use, or tenant mismatch.
type TokenInvalidError struct {
	Reason string
}

func (e TokenInvalidError) Error() string {
	return "invalid token: " + e.Reason
}
