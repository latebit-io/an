package social

// ProviderNotConfiguredError signals a social provider that is unknown or
// not configured (e.g. GOOGLE_CLIENT_ID unset).
type ProviderNotConfiguredError struct {
	Value string
}

func (e ProviderNotConfiguredError) Error() string {
	return "social provider not configured: " + e.Value
}

// SocialTokenInvalidError signals an ID token the provider rejected.
type SocialTokenInvalidError struct {
	Value string
}

func (e SocialTokenInvalidError) Error() string {
	return "invalid social token: " + e.Value
}

// EmailNotVerifiedError signals the provider has not verified the email;
// an refuses to mint an account from an unproven address.
type EmailNotVerifiedError struct {
	Value string
}

func (e EmailNotVerifiedError) Error() string {
	return "social email not verified by provider: " + e.Value
}

// SocialAlreadyLinkedError signals the social identity is linked to a
// different account.
type SocialAlreadyLinkedError struct {
	Value string
}

func (e SocialAlreadyLinkedError) Error() string {
	return "social identity already linked to another account: " + e.Value
}
