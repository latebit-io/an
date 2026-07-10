package apikeys

import "fmt"

type ApiKeyDuplicateError struct {
	Value string `json:"value"`
}

func (e ApiKeyDuplicateError) Error() string {
	return fmt.Sprintf("duplicate api key: '%s' already exists", e.Value)
}

type ApiKeyNotFoundError struct {
	Value string `json:"value"`
}

func (e ApiKeyNotFoundError) Error() string {
	return fmt.Sprintf("api key not found: %s", e.Value)
}

type InvalidApiKeyError struct{}

func (e InvalidApiKeyError) Error() string {
	return "invalid api key"
}

type InvalidApiKeyRequestError struct {
	Value string `json:"value"`
}

func (e InvalidApiKeyRequestError) Error() string {
	return fmt.Sprintf("invalid api key request: %s", e.Value)
}
