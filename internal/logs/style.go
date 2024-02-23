package logs

import "github.com/charmbracelet/lipgloss"

var (
	browseMode = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("6")).
			SetString("Browsing")

	followMode = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("6")).
			SetString("Following")
)

var (
	ColorYellow lipgloss.TerminalColor = lipgloss.CompleteAdaptiveColor{
		Dark:  lipgloss.CompleteColor{TrueColor: "#fada5e", ANSI256: "191", ANSI: "11"},
		Light: lipgloss.CompleteColor{TrueColor: "#ffaf00", ANSI256: "214", ANSI: "3"},
	}

	ColorCyan lipgloss.TerminalColor = lipgloss.CompleteAdaptiveColor{
		Dark:  lipgloss.CompleteColor{TrueColor: "#70C0BA", ANSI256: "37", ANSI: "14"},
		Light: lipgloss.CompleteColor{TrueColor: "#00af87", ANSI256: "36", ANSI: "6"},
	}

	ColorGray lipgloss.TerminalColor = lipgloss.CompleteAdaptiveColor{
		Dark:  lipgloss.CompleteColor{TrueColor: "#808080", ANSI256: "244", ANSI: "7"},
		Light: lipgloss.CompleteColor{TrueColor: "#4e4e4e", ANSI256: "239", ANSI: "8"},
	}
)

var (
	ColorDefaultBackground lipgloss.TerminalColor = lipgloss.AdaptiveColor{Light: "0", Dark: "0"}
	ColorFocusBackground   lipgloss.TerminalColor = lipgloss.AdaptiveColor{Light: "15", Dark: "8"}
)

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
