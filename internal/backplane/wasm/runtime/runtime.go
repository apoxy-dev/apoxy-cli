package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	svcext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	extism "github.com/extism/go-sdk"
	"github.com/tetratelabs/wazero"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/wasm/abi"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/wasm/runtime/fetch"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

const (
	sdkVersion = "v1alpha"
)

// ExecState defines the interface for a single state in the plugin execution.
type ExecState interface {
	// Next advances the state machine to the next state.
	// If the state machine has reached the end state, Next returns nil.
	Next(context.Context, svcext_procv3.ExternalProcessor_ProcessServer) (next ExecState, err error)
}

var (
	_ ExecState = (*StartState)(nil)
	_ ExecState = (*SendDownstreamState)(nil)
)

type execCallback[T any, U any] struct {
	Arg   T
	Err   error
	RetCh chan U
}

type exec struct {
	p *extism.Plugin

	exitCh           chan error
	reqBodyCh        chan *execCallback[*abi.Request, []byte]
	reqSendCh        chan *execCallback[*abi.Request, *abi.Response]
	respBodyCh       chan *execCallback[*abi.Response, []byte]
	respSendCh       chan *execCallback[*abi.Response, error]
	sendDownstreamCh chan *execCallback[*abi.Response, error]
}

var (
	cache  = wazero.NewCompilationCache()
	config = extism.PluginConfig{
		EnableWasi:    true,
		LogLevel:      extism.LogLevelDebug,
		ModuleConfig:  wazero.NewModuleConfig(),
		RuntimeConfig: wazero.NewRuntimeConfig().WithCompilationCache(cache),
	}
)

// StartExec creates a new runtime and returns the initial ExecState.
func StartExec(
	ctx context.Context,
	m extism.Manifest,
) (ExecState, error) {
	return &StartState{
		m: m,
	}, nil
}

// StartState is the initial state of the runtime.
type StartState struct {
	m    extism.Manifest
	exec *exec
}

func abiReqFromProto(
	hdrs []*corev3.HeaderValue,
	attrs map[string]*structpb.Struct,
) *abi.Request {
	abiReq := &abi.Request{
		Header: make(map[string]string),
	}

	method, ok := attrValue[string](attrs, RequestMethodAttr)
	if ok {
		abiReq.Method = *method
	}
	urlPath, ok := attrValue[string](attrs, RequestPathAttr)
	if ok {
		abiReq.URL = *urlPath
	}
	proto, ok := attrValue[string](attrs, RequestProtocolAttr)
	if ok {
		abiReq.Proto = *proto
		major, minor, ok := http.ParseHTTPVersion(*proto)
		if !ok {
			major = 1
			minor = 1
		}
		abiReq.ProtoMajor, abiReq.ProtoMinor = major, minor
	}
	host, ok := attrValue[string](attrs, RequestHostAttr)
	if ok {
		abiReq.Host = *host
	}
	remoteAddr, ok := attrValue[string](attrs, SourceAddressAttr)
	if ok {
		abiReq.RemoteAddr = *remoteAddr
	}
	// For some reason Envoy is passing request.size attribute as a string value.
	contentLen, ok := attrValue[string](attrs, RequestSizeAttr)
	if ok {
		abiReq.ContentLen, _ = strconv.Atoi(*contentLen)
	}

	for _, h := range hdrs {
		abiReq.Header[h.Key] = string(h.RawValue)
	}

	return abiReq
}

func (s *StartState) initExec(
	ctx context.Context,
	_ *svcext_procv3.ProcessingRequest,
) error {
	/*
		m, ok := req.MetadataContext.FilterMetadata[ApoxyMetadataNamespace]
		if !ok {
			return fmt.Errorf("metadata context missing %s", ApoxyMetadataNamespace)
		}
		fn, ok := m.Fields[ApoxyMetadataFunction]
		if !ok {
			return fmt.Errorf("metadata context missing %s", ApoxyMetadataFunction)
		}
		fns := fn.GetStructValue()
		if fns == nil {
			return fmt.Errorf("metadata context field %s is not a struct", ApoxyMetadataFunction)
		}
		fnName := fns.Fields[ApoxyMetadataFunctionName]
		if fnName == nil || fnName.GetStringValue() == "" {
			return fmt.Errorf("metadata context field %s missing %s", ApoxyMetadataFunction, ApoxyMetadataFunctionName)
		}
	*/

	s.exec = &exec{
		exitCh:           make(chan error),
		reqBodyCh:        make(chan *execCallback[*abi.Request, []byte]),
		reqSendCh:        make(chan *execCallback[*abi.Request, *abi.Response]),
		respBodyCh:       make(chan *execCallback[*abi.Response, []byte]),
		respSendCh:       make(chan *execCallback[*abi.Response, error]),
		sendDownstreamCh: make(chan *execCallback[*abi.Response, error]),
	}

	var err error
	s.exec.p, err = extism.NewPlugin(ctx, s.m, config, []extism.HostFunction{
		s.exec.NewReqBodyCallback(),
		s.exec.NewReqSendCallback(),
		s.exec.NewRespBodyCallback(),
		s.exec.NewRespSendCallback(),
		s.exec.NewSendDownstreamCallback(),
		fetch.NewFetchCallback(),
	})
	if err != nil {
		return fmt.Errorf("failed to create plugin: %w", err)
	}

	if !s.exec.p.FunctionExists("_apoxy_sdk_" + sdkVersion) {
		return fmt.Errorf("required SDK version %q is not supported", sdkVersion)
	}
	cfg := s.exec.p.Config
	if cfg == nil {
		cfg = make(map[string]string)
		s.exec.p.Config = cfg
	}
	cfg["sdk_version"] = sdkVersion

	return nil
}

// Next starts the plugin and awaits either Send or request for the body callbacks.
// Returns RequestSendState for former and RequestBodyState for latter as the next state
func (s *StartState) Next(
	ctx context.Context,
	srv svcext_procv3.ExternalProcessor_ProcessServer,
) (ExecState, error) {
	log.Debugf("Starting plugin execution")
	req, err := srv.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive ext_proc request: %w", err)
	}

	if err := s.initExec(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to initialize execution runtime: %w", err)
	}

	var reqHdrs *svcext_procv3.HttpHeaders
	switch req.Request.(type) {
	case *svcext_procv3.ProcessingRequest_RequestHeaders:
		reqHdrs = req.GetRequestHeaders()
		log.Debugf("Received request headers: %v", reqHdrs.GetHeaders().GetHeaders())
	case *svcext_procv3.ProcessingRequest_ResponseHeaders:
		// If we get response headers here, it means that Envoy filter
		// chain got interrupted and we are getting response headers
		// for the immediate response. Do nothing for now.
		log.Debugf("Received response headers")
		return nil, nil
	}
	hdrs := reqHdrs.GetHeaders().GetHeaders()

	abiReq := abiReqFromProto(hdrs, req.GetAttributes())
	reqJson, err := json.Marshal(abiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal abi request: %w", err)
	}

	log.Infof("Starting plugin with request %s -> %s %s/%s",
		abiReq.RemoteAddr, abiReq.Method, abiReq.Host, abiReq.URL)

	_, _, err = s.exec.p.CallWithContext(ctx, "_start", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call _start: %w", err)
	}

	go func() {
		log.Debugf("Calling _apoxy_start")
		exit, _, err := s.exec.p.CallWithContext(ctx, "_apoxy_start", reqJson)
		if err != nil {
			s.exec.exitCh <- fmt.Errorf("failed to call _apoxy_start: %w", err)
		}
		if exit != 0 {
			s.exec.exitCh <- fmt.Errorf("plugin exited with code %d", exit)
		}

		log.Infof("Plugin exited with code %d", exit)

		s.exec.exitCh <- nil
	}()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.exec.exitCh:
			return nil, nil
		case msg := <-s.exec.reqBodyCh:
			log.Debugf("Received request body")
			if msg.Err != nil {
				return nil, msg.Err
			}
			if reqHdrs.EndOfStream {
				log.Debugf("End of stream, no body provided")
				// No body was provided by the downstream, return to the plugin
				// immediately with empty body and wait for Send message.
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-s.exec.exitCh:
					return nil, nil
				case msg.RetCh <- nil:
				}
				continue
			}
			return &RequestBodyState{exec: s.exec, hdrs: hdrs, msg: msg}, nil
		case msg := <-s.exec.reqSendCh:
			log.Debugf("Received send request message")
			if msg.Err != nil {
				log.Debugf("Error in send request: %v", msg.Err)
				return nil, msg.Err
			}
			return &RequestSendState{exec: s.exec, hdrs: hdrs, msg: msg}, nil
		case msg := <-s.exec.sendDownstreamCh:
			log.Debugf("Received send downstream message, code: %d", msg.Arg.StatusCode)
			if msg.Err != nil {
				log.Debugf("Error in send downstream: %v", msg.Err)
				return nil, msg.Err
			}
			return &SendDownstreamState{exec: s.exec, msg: msg}, nil
		}
	}
	panic("unreachable")
}

func headerMutation(
	origHdrs []*corev3.HeaderValue,
	newHdrs map[string]string,
	newContentLen int64,
) *svcext_procv3.HeaderMutation {
	fmt.Printf("Constructing header mutation, orig: %v, new: %v\n", origHdrs, newHdrs)
	setHeaders := []*corev3.HeaderValueOption{}
	for k, v := range newHdrs {
		present := slices.ContainsFunc(origHdrs, func(h *corev3.HeaderValue) bool {
			if h.Key == k && string(h.RawValue) == v {
				return true
			}
			return false
		})
		if present {
			continue
		}

		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key: k,
				// For some reason .Value doesn't work so using RawValue instead.
				RawValue: []byte(v),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	setHeaders = append(setHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:      "content-length",
			RawValue: []byte(strconv.FormatInt(newContentLen, 10)),
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
	})

	rmHeaders := make([]string, 0)
	for _, h := range origHdrs {
		if _, ok := newHdrs[h.Key]; !ok {
			rmHeaders = append(rmHeaders, h.Key)
		}
	}

	return &svcext_procv3.HeaderMutation{
		SetHeaders:    setHeaders,
		RemoveHeaders: rmHeaders,
	}
}

// SendDownstreamState processes the end of the request.
type SendDownstreamState struct {
	exec *exec
	hdrs []*corev3.HeaderValue
	msg  *execCallback[*abi.Response, error]
}

func (s *SendDownstreamState) Next(
	ctx context.Context,
	srv svcext_procv3.ExternalProcessor_ProcessServer,
) (ExecState, error) {
	abiResp := s.msg.Arg
	// Send response back to the Proxy indicating immediate response to downstream.
	resp := &svcext_procv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &svcext_procv3.ImmediateResponse{
			Status: &typev3.HttpStatus{
				Code: typev3.StatusCode(abiResp.StatusCode),
			},
			Headers: headerMutation(nil, abiResp.Header, int64(len(abiResp.Body))),
			Body:    abiResp.Body,
		},
	}
	err := srv.Send(&svcext_procv3.ProcessingResponse{
		Response: resp,
	})
	if err != nil {
		err = fmt.Errorf("failed to send immediate response: %w", err)
		log.Errorf(err.Error())
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exec.exitCh:
		return nil, nil
	case s.msg.RetCh <- err: // Send result back to the plugin.
	}

	// Terminate execution.
	return nil, nil
}
