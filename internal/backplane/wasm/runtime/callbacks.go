package runtime

import (
	"context"
	"encoding/json"
	"fmt"

	extism "github.com/extism/go-sdk"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/wasm/abi"
)

func (e *exec) NewReqBodyCallback() extism.HostFunction {
	return extism.NewHostFunctionWithStack(
		"_apoxy_req_body",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			e.p.Logf(extism.LogLevelDebug, "_apoxy_req_body")
			reqJson, err := p.ReadBytes(stack[0])
			if err != nil {
				e.p.Logf(extism.LogLevelError, "error reading request body: %v", err)
				fmt.Printf("error reading request body: %v\n", err)
				return
			}

			var req abi.Request
			if err := json.Unmarshal(reqJson, &req); err != nil {
				e.p.Logf(extism.LogLevelError, "error unmarshalling request: %v", err)
				fmt.Printf("error unmarshalling request: %v\n", err)
				return
			}

			msg := &execCallback[*abi.Request, []byte]{
				Arg:   &req,
				RetCh: make(chan []byte),
			}
			e.reqBodyCh <- msg
			select {
			case <-ctx.Done():
				return
			case b, ok := <-msg.RetCh:
				if !ok {
					return
				}
				if stack[0], err = p.WriteBytes(b); err != nil {
					return
				}
			}
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)
}

func (e *exec) NewReqSendCallback() extism.HostFunction {
	return extism.NewHostFunctionWithStack(
		"_apoxy_req_send",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			e.p.Logf(extism.LogLevelDebug, "_apoxy_req_send")
			reqJson, err := p.ReadBytes(stack[0])
			if err != nil {
				return
			}
			var req abi.Request
			if err := json.Unmarshal(reqJson, &req); err != nil {
				return
			}

			body, err := p.ReadBytes(stack[1])
			if err != nil {
				return
			}
			req.Body = body

			msg := &execCallback[*abi.Request, *abi.Response]{
				Arg:   &req,
				RetCh: make(chan *abi.Response),
			}
			e.reqSendCh <- msg
			select {
			case <-ctx.Done():
				return
			case resp, ok := <-msg.RetCh:
				if !ok {
					return
				}
				b, err := json.Marshal(resp)
				if err != nil {
					return
				}
				if stack[0], err = p.WriteBytes(b); err != nil {
					return
				}
			}
		},
		[]extism.ValueType{extism.ValueTypePTR, extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)
}
func (e *exec) NewRespBodyCallback() extism.HostFunction {
	return extism.NewHostFunctionWithStack(
		"_apoxy_resp_body",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			e.p.Logf(extism.LogLevelDebug, "_apoxy_resp_body")
			reqJson, err := p.ReadBytes(stack[0])
			if err != nil {
				return
			}

			var resp abi.Response
			if err := json.Unmarshal(reqJson, &resp); err != nil {
				return
			}

			msg := &execCallback[*abi.Response, []byte]{
				Arg:   &resp,
				RetCh: make(chan []byte),
			}
			e.respBodyCh <- msg
			select {
			case <-ctx.Done():
				return
			case b, ok := <-msg.RetCh:
				if !ok {
					return
				}
				if stack[0], err = p.WriteBytes(b); err != nil {
					return
				}
			}
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)
}

func (e *exec) NewRespSendCallback() extism.HostFunction {
	return extism.NewHostFunctionWithStack(
		"_apoxy_resp_send",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			e.p.Logf(extism.LogLevelDebug, "_apoxy_resp_send")
			reqJson, err := p.ReadBytes(stack[0])
			if err != nil {
				return
			}
			var resp abi.Response
			if err := json.Unmarshal(reqJson, &resp); err != nil {
				return
			}

			body, err := p.ReadBytes(stack[1])
			if err != nil {
				return
			}
			resp.Body = body

			msg := &execCallback[*abi.Response, error]{
				Arg:   &resp,
				RetCh: make(chan error),
			}
			e.respSendCh <- msg
			select {
			case <-ctx.Done():
				return
			case err, ok := <-msg.RetCh:
				if !ok {
					return
				}
				var ret int64
				if err != nil {
					ret = 1
				}
				stack[0] = extism.EncodeI64(ret)
			}
		},
		[]extism.ValueType{extism.ValueTypePTR, extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypeI64},
	)
}

func (e *exec) NewSendDownstreamCallback() extism.HostFunction {
	return extism.NewHostFunctionWithStack(
		"_apoxy_send_downstream",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			e.p.Logf(extism.LogLevelDebug, "_apoxy_send_downstream")
			respJson, err := p.ReadBytes(stack[0])
			if err != nil {
				fmt.Printf("error reading response: %v\n", err)
				return
			}
			var resp abi.Response
			if err := json.Unmarshal(respJson, &resp); err != nil {
				fmt.Printf("error unmarshalling response: %v\n", err)
				return
			}

			body, err := p.ReadBytes(stack[1])
			if err != nil {
				fmt.Printf("error reading response body: %v\n", err)
				return
			}
			resp.Body = body

			e.p.Logf(extism.LogLevelDebug, "sending downstream: %v", resp)

			msg := &execCallback[*abi.Response, error]{
				Arg:   &resp,
				RetCh: make(chan error),
			}
			fmt.Printf("sending downstream\n")
			e.sendDownstreamCh <- msg
			fmt.Printf("waiting for send downstream\n")
			select {
			case <-ctx.Done():
				return
			case err, ok := <-msg.RetCh:
				if !ok {
					return
				}
				var ret int64
				if err != nil {
					ret = -1
				}
				stack[0] = extism.EncodeI64(ret)
			}
		},
		[]extism.ValueType{extism.ValueTypePTR, extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypeI64},
	)
}
