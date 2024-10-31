package fetch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	extism "github.com/extism/go-sdk"
	"github.com/vmihailenco/msgpack"
)

type fetchRequest struct {
	URL     string            `msgpack:"url"`
	Method  string            `msgpack:"method"`
	Headers map[string]string `msgpack:"headers"`
}

type fetchResponse struct {
	Status     int               `msgpack:"status"`
	Headers    map[string]string `msgpack:"headers"`
	BodyOffset uint64            `msgpack:"body_offset"`
	Error      string            `msgpack:"error,omitempty"`
}

func fetch(
	ctx context.Context,
	req *fetchRequest,
	body io.Reader,
) (*http.Response, *bytes.Buffer, error) {
	r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating http request: %v", err)
	}

	for k, v := range req.Headers {
		r.Header.Add(k, v)
	}

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, nil, fmt.Errorf("error sending http request: %v", err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, nil, fmt.Errorf("error reading http response body: %v", err)
	}

	return resp, &buf, nil
}

// NewFetchCallback creates a new host function implementing
// the _fetch import.
func NewFetchCallback() extism.HostFunction {
	return extism.NewHostFunctionWithStack(
		"_apoxy_fetch",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			p.Logf(extism.LogLevelDebug, "_fetch")

			rb, err := p.ReadBytes(stack[0])
			if err != nil {
				p.Logf(extism.LogLevelError, "error reading fetch request: %v", err)
				stack[0] = extism.EncodeI64(-1)
				return
			}

			var req fetchRequest
			if err := msgpack.Unmarshal(rb, &req); err != nil {
				p.Logf(extism.LogLevelError, "error decoding fetch request: %v", err)
				stack[0] = extism.EncodeI64(-1)
				return
			}

			var br io.Reader
			bodyOff := stack[1]
			if bodyOff != 0 {
				bb, err := p.ReadBytes(stack[1])
				if err != nil {
					p.Logf(extism.LogLevelError, "error reading fetch request body: %v", err)
					stack[0] = extism.EncodeI64(-1)
					return
				}
				p.Free(stack[1])
				br = bytes.NewReader(bb)
			}

			var fr fetchResponse
			resp, body, err := fetch(ctx, &req, br)
			if err != nil {
				p.Logf(extism.LogLevelError, "error fetching: %v", err)
				fr = fetchResponse{
					Error: err.Error(),
				}
			} else {
				p.Logf(extism.LogLevelDebug, "fetched %s with status %d and %d bytes", req.URL, resp.StatusCode, body.Len())
				bo, err := p.WriteBytes(body.Bytes())
				if err != nil {
					err = fmt.Errorf("error writing fetch response body: %v", err)
					p.Log(extism.LogLevelError, err.Error())
					stack[0] = extism.EncodeI64(-1)
					return
				}
				headers := map[string]string{}
				for k, vs := range resp.Header {
					headers[k] = vs[0]
				}
				fr = fetchResponse{
					Status:     resp.StatusCode,
					Headers:    headers,
					BodyOffset: bo,
				}
			}

			frb, err := msgpack.Marshal(fr)
			if err != nil {
				p.Logf(extism.LogLevelError, "error marshalling fetch response: %v", err)
				stack[0] = extism.EncodeI64(-1)
				return
			}
			if stack[0], err = p.WriteBytes(frb); err != nil {
				p.Logf(extism.LogLevelError, "error writing fetch response: %v", err)
				stack[0] = extism.EncodeI64(-1)
				return
			}
		},
		[]extism.ValueType{extism.ValueTypePTR, extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)
}
