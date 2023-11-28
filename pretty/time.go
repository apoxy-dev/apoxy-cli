package pretty

import (
	"fmt"
	"strings"
	"time"
)

// SinceString returns a string representation of a time.Duration since the provided time.Time.
func SinceString(t time.Time) string {
	d := time.Since(t).Round(time.Second)

	day := time.Hour * 24
	if d < day {
		return d.String()
	}

	var b strings.Builder

	year := day * 365
	if d >= year {
		years := d / year
		fmt.Fprintf(&b, "%dy", years)
		d -= years * year
	}

	days := d / day
	d -= days * day
	fmt.Fprintf(&b, "%dd%s", days, d)

	return b.String()
}
