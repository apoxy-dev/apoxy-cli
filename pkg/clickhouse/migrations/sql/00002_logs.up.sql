CREATE TABLE IF NOT EXISTS {{ .OrgID }}.logs (
	timestamp DateTime64(3, 'UTC'),
	proxy UUID,
	request_id UUID DEFAULT toUUIDOrDefault(JSONExtractString(access_log, 'request_id'), generateUUIDv4()),
	access_log String,
)
ENGINE = MergeTree
ORDER BY (timestamp)
PARTITION BY toYYYYMMDD(timestamp)
TTL toDateTime(timestamp) + INTERVAL {{ .LogsTTL }} HOUR ;
