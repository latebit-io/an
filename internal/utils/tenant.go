package utils

const DefaultTenantID = "default"

// TenantOrDefault maps an empty tenant id to the default tenant.
func TenantOrDefault(tenantID string) string {
	if tenantID == "" {
		return DefaultTenantID
	}
	return tenantID
}
