package logs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type AccessLogMessage struct {
	RequestHost   string `json:"request_host"`
	RequestMethod string `json:"request_method"`
	RequestPath   string `json:"request_path"`
	ResponseCode  int    `json:"response_code"`
	BytesSent     int    `json:"bytes_sent"`
	BytesReceived int    `json:"bytes_received"`
	Duration      int    `json:"duration_ms"`
}

type HttpTraceMessage struct {
	RequestID        string            `json:"request_id"`
	RequestHeaders   map[string]string `json:"request_headers"`
	RequestBody      string            `json:"request_body"`
	RequestTrailers  map[string]string `json:"request_trailers"`
	ResponseHeaders  map[string]string `json:"response_headers"`
	ResponseBody     string            `json:"response_body"`
	ResponseTrailers map[string]string `json:"response_trailers"`
}

type LogRecord struct {
	Timestamp  time.Time    `json:"timestamp"`
	Source     string       `json:"source"`
	RawMessage string       `json:"message"`
	Spans      []*LogRecord `json:"spans"`

	expanded bool
}

func unmarshal(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}

func (l *LogRecord) Message() (interface{}, error) {
	switch l.Source {
	case "access_log":
		var m AccessLogMessage
		if err := unmarshal(l.RawMessage, &m); err != nil {
			return nil, err
		}
		return m, nil
	case "http_trace":
		var m HttpTraceMessage
		if err := unmarshal(l.RawMessage, &m); err != nil {
			return nil, err
		}
		return m, nil
	default:
		return nil, nil
	}
}

const (
	tsFormat = "2006-01-02 15:04:05.000"
)

func (l *LogRecord) RenderLine(width int, inFocus bool) (string, bool, error) {
	msg, err := l.Message()
	if err != nil {
		return "", false, err
	}

	var wire string
	//if level > 0 {
	//	wire = lipgloss.NewStyle().
	//		MarginLeft(level * 2).
	//		Foreground(ColorGray).
	//		Background(ColorDefaultBackground).
	//		Render("└─")
	//}

	bg := ColorDefaultBackground
	if inFocus {
		bg = ColorFocusBackground
	}

	mark := lipgloss.NewStyle().
		Foreground(ColorGray).
		Background(bg).
		Render("▶")
	if l.expanded {
		mark = lipgloss.NewStyle().
			Foreground(ColorGray).
			Background(bg).
			Render("▼")
	}

	switch l.Source {
	case "access_log":
		m := msg.(AccessLogMessage)
		summary := lipgloss.JoinHorizontal(lipgloss.Top,
			wire,
			mark,
			lipgloss.NewStyle().
				Padding(0, 1).
				Foreground(ColorGray).
				Background(bg).
				Width(len(tsFormat)+2).
				Render(l.Timestamp.Format(tsFormat)),
			lipgloss.NewStyle().
				Padding(0, 1).
				Foreground(ColorYellow).
				Background(bg).
				Width(25).
				Render("["+trunc(m.RequestHost, 20)+"]"),
			lipgloss.NewStyle().
				Padding(0, 1).
				Width(9).
				Background(bg).
				Render(trunc(m.RequestMethod, 7)),
			lipgloss.NewStyle().
				Padding(0, 1).
				Width(25).
				Background(bg).
				Render(trunc(m.RequestPath, 23)),
			lipgloss.NewStyle().
				Padding(0, 1).
				Width(5).
				Background(bg).
				Render(strconv.Itoa(m.ResponseCode)),
		)

		if lipgloss.Width(summary) > width {
			return "", false, errors.New("screen too small")
		}

		ss := fmt.Sprintf("(sent: %d, recv: %d, over: %dms)", m.BytesSent, m.BytesReceived, m.Duration)
		// If the summary+stats + padding is too long, we'll just show the summary.
		if lipgloss.Width(summary)+lipgloss.Width(ss)+2 > width {
			return summary, false, nil
		}
		stats := lipgloss.NewStyle().
			Padding(0, 1).
			Width(width - lipgloss.Width(summary)).
			Background(bg).
			Render(ss)
		return lipgloss.JoinHorizontal(lipgloss.Top, summary, stats), false, nil
	case "http_trace":
		return "", false, nil
	}
	return "", false, nil
}

type LogResponse struct {
	Logs  []*LogRecord `json:"logs"`
	Total int          `json:"total"`
}

type LogResponseChunk struct {
	Result *LogRecord `json:"result"`
}

type LogBatch struct {
	Logs []*LogRecord `json:"logs"`
}
