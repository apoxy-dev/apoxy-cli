CREATE TABLE IF NOT EXISTS {{ .OrgID }}.taps (
	_timestamp DateTime64(3, 'UTC'),
	proxy UUID,
	request_id UUID,
	http_trace String,
)
ENGINE = MergeTree
ORDER BY (_timestamp)
PARTITION BY toYYYYMMDD(_timestamp)
TTL toDateTime(_timestamp) + INTERVAL {{ .TapsTTL }} HOUR ;
