package pretty

import (
	"fmt"
	"strconv"
	"time"
)

const (
	timeFormat = "2006-01-02 15:04:05.000Z"

	green        = 32
	yellow       = 33
	blue         = 34
	magenta      = 35
	cyan         = 36
	lightGray    = 37
	darkGray     = 90
	lightRed     = 91
	lightGreen   = 92
	lightYellow  = 93
	lightBlue    = 94
	lightMagenta = 95
	lightCyan    = 96
	white        = 97

	reset = "\033[0m"
)

func colorize(s string, color int) string {
	return fmt.Sprintf("\033[%dm%s%s", color, s, reset)
}

// PrintLn prints a log line with a timestamp and source.
func PrintLn(t time.Time, id, spanid int, source string, message string) {
	fmt.Printf("%s %s %s [%s] %s\n",
		colorize(t.Format(timeFormat), darkGray),
		colorize(strconv.Itoa(id), lightGreen),
		colorize(strconv.Itoa(spanid), lightYellow),
		colorize(source, lightYellow),
		colorize(message, cyan))
}
