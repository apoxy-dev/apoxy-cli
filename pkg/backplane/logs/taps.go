package logs

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tapv3 "github.com/envoyproxy/go-control-plane/envoy/data/tap/v3"
	"github.com/fsnotify/fsnotify"
	"github.com/goccy/go-json"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

type httpTrace struct {
	RequestID        string            `json:"request_id"`
	RequestHeaders   map[string]string `json:"request_headers"`
	RequestBody      string            `json:"request_body"`
	RequestTrailers  map[string]string `json:"request_trailers"`
	ResponseHeaders  map[string]string `json:"response_headers"`
	ResponseBody     string            `json:"response_body"`
	ResponseTrailers map[string]string `json:"response_trailers"`
}

// headerValForKey returns the value of the first header with the given key.
func headerValForKey(hdrs []*corev3.HeaderValue, key string) string {
	for _, h := range hdrs {
		if h.GetKey() == key {
			return h.GetValue()
		}
	}
	return ""
}

// matchHeaderKeyVal returns true if the headers contain a header with the given key and value prefix.
func matchHeaderKeyVal(hdrs []*corev3.HeaderValue, key, valPrefix string) bool {
	for _, h := range hdrs {
		if h.GetKey() == key && strings.HasPrefix(h.GetValue(), valPrefix) {
			return true
		}
	}
	return false
}

// headersToMap converts a slice of headers to a map. Duplicate keys are joined with a comma.
func headersToMap(hdrs []*corev3.HeaderValue) map[string]string {
	var m = make(map[string]string)
	for _, h := range hdrs {
		if _, ok := m[h.GetKey()]; ok {
			m[h.GetKey()] += "," + h.GetValue()
		} else {
			m[h.GetKey()] = h.GetValue()
		}
	}
	return m
}

func extractJsonBody(msg *tapv3.HttpBufferedTrace_Message, isJson bool) (string, error) {
	if msg.GetBody() == nil {
		return "", nil
	}

	// Check if the body is JSON based on content-type header.
	if !matchHeaderKeyVal(msg.GetHeaders(), "content-type", "application/json") &&
		!matchHeaderKeyVal(msg.GetHeaders(), "content-type", "text/plain") {
		return "", nil
	}

	var body strings.Builder
	switch b := msg.GetBody().GetBodyType().(type) {
	case *tapv3.Body_AsString:
		body.WriteString(b.AsString)
	case *tapv3.Body_AsBytes:
		// Json as bytes is base64 encoded.
		if isJson {
			dec := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(b.AsBytes))
			if _, err := io.Copy(&body, dec); err != nil {
				return "", fmt.Errorf("failed to decode body: %w", err)
			}
		} else {
			body.Write(b.AsBytes)
		}
	default:
		return "", fmt.Errorf("unknown body type: %T", b)
	}
	return body.String(), nil
}

func decodeBody(body, enc string) (string, error) {
	var (
		b   strings.Builder
		dec io.ReadCloser
	)

	switch enc {
	case "gzip":
		var err error
		dec, err = gzip.NewReader(strings.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("failed to create gzip reader: %w", err)
		}
	case "deflate":
		dec = flate.NewReader(strings.NewReader(body))
	case "":
		return body, nil
	default:
		return "", fmt.Errorf("unknown encoding: %s", enc)
	}
	defer dec.Close()

	if _, err := io.Copy(&b, dec); err != nil {
		return "", fmt.Errorf("failed to decode body: %w", err)
	}

	return b.String(), nil
}

func (lc *chLogsCollector) writeTaps(ctx context.Context, isJson bool, w *tapv3.TraceWrapper) error {
	reqHdrs := w.GetHttpBufferedTrace().GetRequest().GetHeaders()
	reqID := headerValForKey(reqHdrs, "x-request-id")
	if reqID == "" {
		return fmt.Errorf("failed to get request id from tap wrapper: %v", reqHdrs)
	}

	reqBody, err := extractJsonBody(w.GetHttpBufferedTrace().GetRequest(), isJson)
	if err != nil {
		return fmt.Errorf("failed to extract request body: %w", err)
	}
	cEnc := headerValForKey(reqHdrs, "content-encoding")
	reqBody, err = decodeBody(reqBody, cEnc)
	if err != nil {
		return fmt.Errorf("failed to decode request body: %w", err)
	}

	respBody, err := extractJsonBody(w.GetHttpBufferedTrace().GetResponse(), isJson)
	if err != nil {
		return fmt.Errorf("failed to extract response body: %w", err)
	}
	cEnc = headerValForKey(w.GetHttpBufferedTrace().GetResponse().GetHeaders(), "content-encoding")
	respBody, err = decodeBody(respBody, cEnc)
	if err != nil {
		return fmt.Errorf("failed to decode response body: %w", err)
	}

	httpTraceJson, err := json.Marshal(&httpTrace{
		RequestID:        reqID,
		RequestHeaders:   headersToMap(w.GetHttpBufferedTrace().GetRequest().GetHeaders()),
		RequestBody:      reqBody,
		RequestTrailers:  headersToMap(w.GetHttpBufferedTrace().GetRequest().GetTrailers()),
		ResponseHeaders:  headersToMap(w.GetHttpBufferedTrace().GetResponse().GetHeaders()),
		ResponseBody:     respBody,
		ResponseTrailers: headersToMap(w.GetHttpBufferedTrace().GetResponse().GetTrailers()),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal tap wrapper: %w", err)
	}

	return lc.chConn.AsyncInsert(
		ctx,
		`INSERT INTO taps (_timestamp, proxy, request_id, http_trace) VALUES (?, ?, ?, ?)`,
		// Don't wait for insert to complete (requires retry logic in tailer).
		false, // wait
		time.Now().UnixMilli(),
		lc.proxyUID,
		reqID,
		string(httpTraceJson),
	)
}

func parseTraceWrapper(path string) (*tapv3.TraceWrapper, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to open file: %s, skipping", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to read file: %s, skipping", err)
	}

	var isJson bool
	w := &tapv3.TraceWrapper{}
	switch filepath.Ext(path) {
	case ".json":
		isJson = true
		if err := protojson.Unmarshal(data, w); err != nil {
			return nil, false, fmt.Errorf("Failed to unmarshal json: %s", err)
		}
	case ".pb":
		if err := proto.Unmarshal(data, w); err != nil {
			return nil, false, fmt.Errorf("Failed to unmarshal proto: %s", err)
		}
	}

	return w, isJson, nil
}

func (lc *chLogsCollector) processTapsDir(ctx context.Context, dirPath string) error {
	log.Debugf("Processing tap dir: %s", dirPath)
	return fs.WalkDir(os.DirFS(dirPath), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "." {
			return nil
		}
		if d.IsDir() {
			log.Warnf("Found unexpected directory: %s", path)
			return fs.SkipDir
		}

		// Skip files that are not .json or pb.
		if filepath.Ext(path) != ".json" && filepath.Ext(path) != ".pb" {
			log.Warnf("Found unexpected file: %s, skipping", path)
			return nil
		}

		w, isJson, err := parseTraceWrapper(filepath.Join(dirPath, path))
		if err != nil {
			log.Errorf("Failed to parse trace wrapper: %s", err)
			// Remove the file so we don't keep trying to parse it.
			if err := os.Remove(filepath.Join(dirPath, path)); err != nil {
				log.Errorf("Failed to remove file: %s", err)
			}
			return nil
		}

		if err := lc.writeTaps(ctx, isJson, w); err != nil {
			log.Errorf("Failed to process tap: %s", err)
			return nil // Will retry on next iteration.
		}

		if err := os.Remove(filepath.Join(dirPath, path)); err != nil {
			log.Errorf("Failed to remove file: %s", err)
		}

		return nil
	})
}

// CollectTaps collects taps from a directory and writes them to logs sink.
func (lc *chLogsCollector) CollectTaps(ctx context.Context, dirPath string) error {
	log.Infof("Collecting taps from: %s", dirPath)
	ds, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("Failed to create taps dir: %s", err)
		}
	} else if err != nil {
		return fmt.Errorf("Failed to stat directory: %s", err)
	} else if !ds.IsDir() {
		return fmt.Errorf("%s is not a directory", dirPath)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("Failed to create watcher: %s", err)
	}
	defer watcher.Close()
	if err := watcher.Add(dirPath); err != nil {
		return fmt.Errorf("Failed to add directory to watcher: %s", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
			if err := lc.processTapsDir(ctx, dirPath); err != nil {
				log.Errorf("Failed to process taps dir: %s", err)
			}
		case ev, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("Watcher closed")
			}

			log.Debugf("Event %v: %s", ev.Op, ev.Name)

			if !ev.Has(fsnotify.Write) {
				continue
			}

			if err := lc.processTapsDir(ctx, dirPath); err != nil {
				log.Errorf("Failed to process taps dir: %s", err)
			}
		case err := <-watcher.Errors:
			log.Warnf("Watcher error: %s", err)
		}
	}
}
