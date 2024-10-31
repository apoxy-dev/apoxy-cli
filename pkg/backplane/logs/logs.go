// Package logs provides logging facilities for Envoy.
package logs

import (
	"context"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

type LogsCollector interface {
	// CollectAccessLogs collects access logs from the given path.
	CollectAccessLogs(ctx context.Context, path string) error

	// CollectTaps collects Envoy taps from the given path.
	CollectTaps(ctx context.Context, path string) error
}

type chLogsCollector struct {
	proxyUID uuid.UUID
	chConn   clickhouse.Conn
}

// NewClickHouseLogsCollector creates a new LogsCollector that writes logs to ClickHouse.
func NewClickHouseLogsCollector(
	chConn clickhouse.Conn,
	proxyUID uuid.UUID,
) LogsCollector {
	return &chLogsCollector{
		proxyUID: proxyUID,
		chConn:   chConn,
	}
}
