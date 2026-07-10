package accounts

// AccountNotFoundError signals the account does not exist (or is deleted).
type AccountNotFoundError struct {
	Value string
}

func (e AccountNotFoundError) Error() string {
	return "account not found: " + e.Value
}

// AccountDuplicateError signals an account already exists for the email.
type AccountDuplicateError struct {
	Value string
}

func (e AccountDuplicateError) Error() string {
	return "account already exists: " + e.Value
}

// AccountNotVerifiedError signals the account has not verified its email.
type AccountNotVerifiedError struct {
	Value string
}

func (e AccountNotVerifiedError) Error() string {
	return "account not verified: " + e.Value
}

// AccountDisabledError signals the account is disabled.
type AccountDisabledError struct {
	Value string
}

func (e AccountDisabledError) Error() string {
	return "account disabled: " + e.Value
}

// InvalidAccountError signals invalid registration or update input.
type InvalidAccountError struct {
	Value string
}

func (e InvalidAccountError) Error() string {
	return "invalid account: " + e.Value
}

// VerificationError signals a failed email verification attempt.
type VerificationError struct {
	Value string
}

func (e VerificationError) Error() string {
	return "verification failed: " + e.Value
}

// ResetTokenInvalidError signals a missing or wrong password reset token.
type ResetTokenInvalidError struct{}

func (e ResetTokenInvalidError) Error() string {
	return "invalid reset token"
}

// ResetTokenExpiredError signals an expired password reset token.
type ResetTokenExpiredError struct{}

func (e ResetTokenExpiredError) Error() string {
	return "reset token expired"
}
