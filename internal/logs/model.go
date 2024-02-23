// Package logs provides log viewing functionality for the Apoxy CLI.
package logs

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	records   []*LogRecord
	follow    bool
	nextBatch func() (*LogBatch, error)

	// cursor is the index of the currently selected log line in the interval
	// [0, len(<rendered lines>)).
	cursor int
	// frameStart is the index of the first (top) log line to display in the current
	// viewing frame.
	frameStart    int
	width, height int
	quitting      bool
}

// NewModel returns a new Bubble Tea model.
func NewModel(
	records []*LogRecord,
	follow bool,
	nextBatch func() (*LogBatch, error),
) tea.Model {
	return &model{
		records:   records,
		follow:    follow,
		nextBatch: nextBatch,
	}
}

type followMsg struct{}

func Follow() tea.Msg {
	return followMsg{}
}

func followTick() tea.Cmd {
	return tea.Every(100*time.Millisecond, func(_ time.Time) tea.Msg {
		return Follow()
	})
}

func (m *model) Init() tea.Cmd {
	return followTick()
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "j", "down":
			m.cursor++
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "f", "ctrl+f", "page down":
			m.cursor += m.height - 3
		case "b", "ctrl+b", "page up":
			m.cursor -= m.height - 3
			if m.cursor < 0 {
				m.cursor = 0
			}
		}
		return m, nil
	case followMsg:
		// If we're not following the logs, just render the current state.
		//if !m.follow {
		//	return m, nil
		//}

		// If we are following the logs, fetch the latest logs and update the model.
		return m, followTick()
	default:
	}
	return m, nil
}

func (m *model) adjustFrame(max, h int) {
	if m.cursor < 0 {
		m.cursor = 0
	} else if m.cursor >= max {
		m.cursor = max - 1
	}

	// Adjust the frameStart index to keep the cursor in view.
	if m.cursor >= m.frameStart+h-1 {
		m.frameStart = m.cursor - h + 1
	}
	if m.cursor < m.frameStart {
		m.frameStart = m.cursor
	}
}

func (m *model) logsView(w, h int) (string, error) {
	var lines []string
	// For each log record, render the log lines one by one
	// and append them to the background buffer.
	for _, r := range m.records {
		for {
			line, ok, err := r.RenderLine(w-2, m.cursor == len(lines))
			if err != nil {
				return "", err
			}
			lines = append(lines, line)
			if !ok {
				break
			}
		}
	}

	// Adjust the frameStart index to keep the cursor in view.
	m.adjustFrame(len(lines), h)

	// Reslice the lines to the current position of the frame.
	frameEnd := m.frameStart + h
	if frameEnd >= len(lines) {
		frameEnd = len(lines)
	}
	lines = lines[m.frameStart:frameEnd]

	return lipgloss.NewStyle().
		Width(w - 2).
		Height(h).
		Border(lipgloss.NormalBorder()).
		Render(lipgloss.JoinVertical(lipgloss.Top, lines...)), nil
}

func (m *model) View() string {
	if m.quitting {
		return "Quitting..."
	}

	mode := browseMode.String()
	if m.follow {
		mode = followMode.String()
	}

	statusBar := lipgloss.JoinHorizontal(lipgloss.Left,
		mode,
		lipgloss.NewStyle().
			Padding(0, 1).
			Background(lipgloss.Color("7")).
			Width(m.width-lipgloss.Width(mode)).
			Render(""),
	)

	helpBar := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("8")).
			Width(m.width).
			SetString("Press 'h' to toggle help").
			Render(""),
	)

	logsView, err := m.logsView(
		m.width,
		m.height-lipgloss.Height(statusBar)-lipgloss.Height(helpBar)-2,
	)
	if err != nil {
		return err.Error()
	}

	return lipgloss.JoinVertical(lipgloss.Top,
		statusBar,
		logsView,
		helpBar,
	)
}
