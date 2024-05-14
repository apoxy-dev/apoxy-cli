package build

import (
	"fmt"
	"strings"
)

var (
	buildVersion = "0.0.0-dev"
	BuildVersion = buildVersion
	BuildDate    = "n/a"
	CommitHash   = "n/a"
)

// IsDev returns true if the build is a development build.
func IsDev() bool {
	return strings.HasSuffix(BuildVersion, "-dev")
}

// Version returns the version string in the format of "vX.Y.Z (<commit>), built <date>".
func Version() string {
	if BuildVersion == buildVersion {
		return BuildVersion
	}
	return fmt.Sprintf("v%s (%s), built %s", BuildVersion, CommitHash, BuildDate)
}

// UserAgent returns the user agent string.
func UserAgent() string {
	if BuildVersion == "dev" {
		return fmt.Sprintf("apoxy-cli/%s", BuildVersion)
	}
	return fmt.Sprintf("apoxy-cli/v%s-%s (%s)", BuildVersion, CommitHash, BuildDate)
}
