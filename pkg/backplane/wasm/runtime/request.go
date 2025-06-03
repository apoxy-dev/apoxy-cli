package runtime

import (
	"context"
	"fmt"
	"strconv"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	httpext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	svcext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/abi"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var (
	_ ExecState = (*RequestBodyState)(nil)
	_ ExecState = (*RequestSendState)(nil)
)

// RequestBodyState processes the request body.
type RequestBodyState struct {
	exec *exec
	hdrs []*corev3.HeaderValue
	msg  *execCallback[*abi.Request, []byte]
}

// Next implements the ExecState interface.
func (s *RequestBodyState) Next(
	ctx context.Context,
	srv svcext_procv3.ExternalProcessor_ProcessServer,
) (ExecState, error) {
	abiReq := s.msg.Arg
	resp := &svcext_procv3.ProcessingResponse_RequestHeaders{
		RequestHeaders: &svcext_procv3.HeadersResponse{
			Response: &svcext_procv3.CommonResponse{
				HeaderMutation:  headerMutation(s.hdrs, abiReq.Header, 0),
				ClearRouteCache: true, // TBD(dsky): Conditionally clear cache based on header mutations.
			},
		},
	}
	err := srv.Send(&ext_procv3.ProcessingResponse{
		Response: resp,
		ModeOverride: &httpext_procv3.ProcessingMode{
			RequestBodyMode: httpext_procv3.ProcessingMode_BUFFERED,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed sending request headers response: %w", err)
	}

	req, err := srv.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed receiving request body: %w", err)
	}
	reqBody := req.GetRequestBody()
	if reqBody == nil {
		return nil, fmt.Errorf("expected request body, got %T", req)
	}

	// Send the request body to the plugin.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case s.msg.RetCh <- reqBody.Body:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case msg := <-s.exec.reqSendCh:
		if msg.Err != nil {
			return nil, msg.Err
		}
		return &RequestSendState{
			exec:      s.exec,
			hdrs:      s.hdrs,
			bodyPhase: true, // Indicates the response must be ProcessingResponse_RequestBody
			msg:       msg,
		}, nil
	case msg := <-s.exec.sendDownstreamCh:
		if msg.Err != nil {
			return nil, msg.Err
		}
		return &SendDownstreamState{exec: s.exec, msg: msg}, nil
	}
	panic("unreachable")
}

// RequestSendState processes request send operation.
type RequestSendState struct {
	exec      *exec
	hdrs      []*corev3.HeaderValue
	bodyPhase bool
	msg       *execCallback[*abi.Request, *abi.Response]
}

func abiRespFromProto(
	hdrs []*corev3.HeaderValue,
	attrs map[string]*structpb.Struct,
) *abi.Response {
	abiResp := &abi.Response{
		Header: make(map[string]string),
	}
	for _, h := range hdrs {
		abiResp.Header[h.Key] = string(h.RawValue)
	}

	abiResp.StatusCode, _ = strconv.Atoi(abiResp.Header[string(ResponseStatus)])
	// For some reason Envoy is passing request.size attribute as a string value.
	contentLen, ok := attrValue[string](attrs, ResponseSizeAttr)
	if ok {
		abiResp.ContentLen, _ = strconv.Atoi(*contentLen)
	}

	return abiResp
}

// Next will send the result of the Send operation to the plugin and wait for the next action.
func (s *RequestSendState) Next(
	ctx context.Context,
	srv svcext_procv3.ExternalProcessor_ProcessServer,
) (ExecState, error) {
	abiReq := s.msg.Arg
	log.Debugf("Sending request reply to Proxy")
	pr := &svcext_procv3.ProcessingResponse{}
	cr := &svcext_procv3.CommonResponse{
		HeaderMutation: headerMutation(s.hdrs, abiReq.Header, int64(len(abiReq.Body))),
		BodyMutation: &svcext_procv3.BodyMutation{
			Mutation: &svcext_procv3.BodyMutation_Body{
				Body: abiReq.Body,
			},
		},
		ClearRouteCache: true, // TBD
	}
	if s.bodyPhase {
		pr.Response = &svcext_procv3.ProcessingResponse_RequestBody{
			RequestBody: &svcext_procv3.BodyResponse{
				Response: cr,
			},
		}
	} else {
		// If we want body mutation to be applied, need to set status to CONTINUE_AND_REPLACE.
		cr.Status = svcext_procv3.CommonResponse_CONTINUE_AND_REPLACE
		pr.Response = &svcext_procv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &svcext_procv3.HeadersResponse{
				Response: cr,
			},
		}
	}
	err := srv.Send(pr)
	if err != nil {
		return nil, fmt.Errorf("failed sending response: %w", err)
	}

	req, err := srv.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed receiving response headers: %w", err)
	}
	respHdrs := req.GetResponseHeaders()
	if respHdrs == nil {
		return nil, fmt.Errorf("expected response headers, got %T", req)
	}
	hdrs := respHdrs.GetHeaders().GetHeaders()

	abiResp := abiRespFromProto(hdrs, req.Attributes)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case s.msg.RetCh <- abiResp:
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.exec.exitCh:
			return nil, nil
		case msg := <-s.exec.respBodyCh:
			if msg.Err != nil {
				return nil, msg.Err
			}
			if respHdrs.EndOfStream {
				// Upstream did not send a body, so reply to plugin with an empty body
				// and wait for Send message.
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-s.exec.exitCh:
					return nil, nil
				case msg.RetCh <- nil:
				}
				continue
			}
			return &ResponseBodyState{exec: s.exec, hdrs: hdrs, msg: msg}, nil
		case msg := <-s.exec.respSendCh:
			if msg.Err != nil {
				return nil, msg.Err
			}
			return &ResponseSendState{exec: s.exec, hdrs: hdrs, msg: msg}, nil
		case msg := <-s.exec.sendDownstreamCh:
			if msg.Err != nil {
				return nil, msg.Err
			}
			return &SendDownstreamState{exec: s.exec, msg: msg}, nil
		}
	}
	panic("unreachable")
}
