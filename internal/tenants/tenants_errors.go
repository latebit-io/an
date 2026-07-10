package tenants

import "fmt"

// TenantNotFoundError signals the tenant does not exist.
type TenantNotFoundError struct {
	Value string
}

func (e TenantNotFoundError) Error() string {
	return fmt.Sprintf("tenant not found: %s", e.Value)
}
