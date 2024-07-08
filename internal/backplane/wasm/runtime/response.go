package runtime

import (
	"context"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	httpext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	svcext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/wasm/abi"
)

var (
	_ ExecState = (*ResponseBodyState)(nil)
	_ ExecState = (*ResponseSendState)(nil)
)

// ResponseBodyState requests the response body from the Proxy, passes it the
// plugin, and awaits one of the following:
// - a response to be sent upstream
// - an immediate response to be sent downstream (with no further processing)
// - runtime exit
type ResponseBodyState struct {
	exec *exec
	hdrs []*corev3.HeaderValue
	msg  *execCallback[*abi.Response, []byte]
}

// Next implements the ExecState interface.
func (s *ResponseBodyState) Next(
	ctx context.Context,
	srv svcext_procv3.ExternalProcessor_ProcessServer,
) (ExecState, error) {
	abiResp := s.msg.Arg
	resp := &svcext_procv3.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &svcext_procv3.HeadersResponse{
			Response: &svcext_procv3.CommonResponse{
				HeaderMutation: headerMutation(s.hdrs, abiResp.Header, 0),
				BodyMutation: &svcext_procv3.BodyMutation{
					Mutation: &svcext_procv3.BodyMutation_Body{
						Body: abiResp.Body,
					},
				},
				ClearRouteCache: true, // TBD
			},
		},
	}
	err := srv.Send(&ext_procv3.ProcessingResponse{
		Response: resp,
		ModeOverride: &httpext_procv3.ProcessingMode{
			ResponseBodyMode: httpext_procv3.ProcessingMode_BUFFERED,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed requesting response body: %w", err)
	}

	// Receive response body in the next request message from the Proxy.
	req, err := srv.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed receiving response body: %w", err)
	}
	respBody := req.GetResponseBody()
	if respBody == nil {
		return nil, fmt.Errorf("expected response body, got %T", req)
	}

	// Send response body back to the requesting plugin.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case s.msg.RetCh <- respBody.Body: // TODO(dsky): This should also pass the error from above.
	}

	// Block until further interrupts from the plugin.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case msg := <-s.exec.respSendCh:
		if msg.Err != nil {
			return nil, msg.Err
		}
		return &ResponseSendState{exec: s.exec, bodyPhase: true, msg: msg}, nil
	case msg := <-s.exec.sendDownstreamCh:
		if msg.Err != nil {
			return nil, msg.Err
		}
		return &SendDownstreamState{exec: s.exec, msg: msg}, nil
	}
	panic("unreachable")
}

// ResponseSendState sends the response to the Proxy (either a header or body response
// depending on the phase) and concludes the execution.
type ResponseSendState struct {
	exec      *exec
	hdrs      []*corev3.HeaderValue
	bodyPhase bool
	msg       *execCallback[*abi.Response, error]
}

// Next implements the ExecState interface.
func (s *ResponseSendState) Next(
	ctx context.Context,
	srv svcext_procv3.ExternalProcessor_ProcessServer,
) (ExecState, error) {
	abiResp := s.msg.Arg
	fmt.Printf("ResponseSendState.Next: %v\n", abiResp)
	pr := &svcext_procv3.ProcessingResponse{}
	abiResp.Header[string(ResponseStatus)] = fmt.Sprintf("%d", abiResp.StatusCode)
	cr := &svcext_procv3.CommonResponse{
		HeaderMutation: headerMutation(s.hdrs, abiResp.Header, int64(len(abiResp.Body))),
		BodyMutation: &svcext_procv3.BodyMutation{
			Mutation: &svcext_procv3.BodyMutation_Body{
				Body: abiResp.Body,
			},
		},
		ClearRouteCache: true, // TBD
	}
	fmt.Printf("Body mutation: %v\n", string(cr.BodyMutation.Mutation.(*svcext_procv3.BodyMutation_Body).Body))
	if s.bodyPhase {
		pr.Response = &svcext_procv3.ProcessingResponse_ResponseBody{
			ResponseBody: &svcext_procv3.BodyResponse{
				Response: cr,
			},
		}
	} else {
		// If we want body mutation to be applied, need to set status to CONTINUE_AND_REPLACE.
		cr.Status = svcext_procv3.CommonResponse_CONTINUE_AND_REPLACE
		pr.Response = &svcext_procv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &svcext_procv3.HeadersResponse{
				Response: cr,
			},
		}
	}
	err := srv.Send(pr)
	if err != nil {
		fmt.Printf("Error sending response: %v\n", err)
		err = fmt.Errorf("failed sending response body: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case s.msg.RetCh <- err:
	}

	return nil, nil
}
