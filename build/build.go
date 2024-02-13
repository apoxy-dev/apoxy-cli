package build

import (
	"fmt"
)

var (
	buildVersion = "0.0.0-dev"
	BuildVersion = buildVersion
	BuildDate    = "n/a"
	CommitHash   = "n/a"
)

func Version() string {
	if BuildVersion == buildVersion {
		return BuildVersion
	}
	return fmt.Sprintf("v%s (%s), built %s", BuildVersion, CommitHash, BuildDate)
}

func UserAgent() string {
	if BuildVersion == "dev" {
		return fmt.Sprintf("apoxy-cli/%s", BuildVersion)
	}
	return fmt.Sprintf("apoxy-cli/v%s-%s (%s)", BuildVersion, CommitHash, BuildDate)
}
