package logs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/goccy/go-json"

	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/logs/logtail"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

var (
	accessLogRegex = regexp.MustCompile(`\[(.*?)\] "(.*?) (.*?) (.*?)" (\d+) (\S+) (\d+) (\d+) (\d+) (\d+) "(.*?)" "(.*?)" "(.*?)" "(.*?)" "(.*?)"`)
)

type accessLogEntry struct {
	StartTime           time.Time `json:"start_time"`
	RequestMethod       string    `json:"request_method"`
	RequestPath         string    `json:"request_path"`
	Protocol            string    `json:"protocol"`
	ResponseCode        int       `json:"response_code"`
	ResponseFlags       string    `json:"response_flags"`
	BytesReceived       int       `json:"bytes_received"`
	BytesSent           int       `json:"bytes_sent"`
	Duration            int       `json:"duration_ms"`
	UpstreamServiceTime int       `json:"upstream_service_time_ms"`
	RequestForwardedFor string    `json:"request_forwarded_for"`
	RequestUserAgent    string    `json:"request_user_agent"`
	RequestID           string    `json:"request_id"`
	RequestHost         string    `json:"request_host"`
	UpstreamHost        string    `json:"upstream_host"`
}

func toInt(s []byte) int {
	var i int
	fmt.Sscanf(string(s), "%d", &i)
	return i
}

func parseAccessLog(data []byte, entry *accessLogEntry) error {
	matches := accessLogRegex.FindSubmatch(data)
	if len(matches) != 16 {
		return fmt.Errorf("invalid access log entry: %s", string(data))
	}
	var err error
	entry.StartTime, err = time.Parse(time.RFC3339Nano, string(matches[1]))
	if err != nil {
		return err
	}
	entry.RequestMethod = string(matches[2])
	entry.RequestPath = string(matches[3])
	entry.Protocol = string(matches[4])
	entry.ResponseCode = toInt(matches[5])
	entry.ResponseFlags = string(matches[6])
	entry.BytesReceived = toInt(matches[7])
	entry.BytesSent = toInt(matches[8])
	entry.Duration = toInt(matches[9])
	entry.UpstreamServiceTime = toInt(matches[10])
	entry.RequestForwardedFor = string(matches[11])
	entry.RequestUserAgent = string(matches[12])
	entry.RequestID = string(matches[13])
	entry.RequestHost = string(matches[14])
	entry.UpstreamHost = string(matches[15])
	return nil
}

func (lc *chLogsCollector) writeAccessLog(ctx context.Context, data []byte) error {
	var entry accessLogEntry
	if err := parseAccessLog(data, &entry); err != nil {
		return err
	}
	entryJson, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal access log entry: %w", err)
	}
	log.Debugf("timestamp: %s, request_id: %s, request_path: %s", entry.StartTime, entry.RequestID, entry.RequestPath)
	return lc.chConn.AsyncInsert(
		ctx,
		`INSERT INTO logs (timestamp, proxy, access_log) VALUES (?, ?, ?)`,
		// TODO(dsky): Wait for insert to complete (requires retry logic in tailer).
		false, // wait
		entry.StartTime.UnixMilli(),
		lc.proxyUID,
		string(entryJson),
	)
}

// CollectAccessLogs collects access logs from the given path.
func (lc *chLogsCollector) CollectAccessLogs(ctx context.Context, path string) error {
	fs, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if _, err := os.Create(path); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat access log path: %w", err)
	} else if fs.IsDir() {
		return fmt.Errorf("access log path is a directory: %s", path)
	}

	return logtail.Tail(ctx, path, func(data []byte) error {
		log.Debugf("[accesslogs] %s", data)
		if err := lc.writeAccessLog(ctx, data); err != nil {
			log.Errorf("writeAccessLog() returned: %v", err)
		}
		return nil
	})
}
