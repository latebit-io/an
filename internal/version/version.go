package version

// These variables will be populated by GoReleaser during build
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

// GetVersionInfo returns formatted version information
func GetVersionInfo() string {
	return "Version: " + Version + " | Commit: " + Commit + " | Built at: " + BuildTime
}
