package build

import (
	"fmt"
)

var (
	BuildVersion = "dev"
	BuildDate    = "n/a"
	CommitHash   = "n/a"
)

func Version() string {
	if BuildVersion == "dev" {
		return BuildVersion
	}
	return fmt.Sprintf("v%s, built %s", BuildVersion, CommitHash, BuildDate)
}

func UserAgent() string {
	if BuildVersion == "dev" {
		return fmt.Sprintf("apoxy-cli/%s", BuildVersion)
	}
	return fmt.Sprintf("apoxy-cli/v%s-%s (%s)", BuildVersion, CommitHash, BuildDate)
}
