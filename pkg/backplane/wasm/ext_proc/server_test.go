package ext_proc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	svcext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/testing/protocmp"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/wasm/runtime"
)

var (
	fakeSrv *httptest.Server
)

func init() {
	fakeSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/echo" {
			if _, err := io.Copy(w, r.Body); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func newMetadata(name string) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"func": {
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"name": {
								Kind: &structpb.Value_StringValue{
									StringValue: name,
								},
							},
						},
					},
				},
			},
		},
	}
}

type step struct {
	request  *svcext_procv3.ProcessingRequest
	wantEOF  bool
	wantErr  error
	wantResp *svcext_procv3.ProcessingResponse
}

func TestServer(t *testing.T) {
	ar, err := txtar.ParseFile("testdata/js.txtar")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		scriptTxtar string
		steps       []step
	}{
		{
			name:        "hello",
			scriptTxtar: "hello.js",
			steps: []step{
				{
					request: &svcext_procv3.ProcessingRequest{
						MetadataContext: &corev3.Metadata{
							FilterMetadata: map[string]*structpb.Struct{},
						},
						Attributes: map[string]*structpb.Struct{
							"envoy.filters.http.ext_proc": {
								Fields: map[string]*structpb.Value{
									runtime.RequestMethodAttr.String(): {
										Kind: &structpb.Value_StringValue{
											StringValue: "GET",
										},
									},
								},
							},
						},
						Request: &svcext_procv3.ProcessingRequest_RequestHeaders{
							RequestHeaders: &svcext_procv3.HttpHeaders{
								Headers: &corev3.HeaderMap{
									Headers: []*corev3.HeaderValue{
										{
											Key:      ":method",
											RawValue: []byte(""),
										},
										{
											Key:      ":authority",
											RawValue: []byte("localhost"),
										},
									},
								},
							},
						},
					},
					wantEOF: true,
				},
			},
		},
		{
			name:        "echo",
			scriptTxtar: "echo.js",
			steps: []step{
				{
					request: &svcext_procv3.ProcessingRequest{
						MetadataContext: &corev3.Metadata{
							FilterMetadata: map[string]*structpb.Struct{},
						},
						Attributes: map[string]*structpb.Struct{
							"envoy.filters.http.ext_proc": {
								Fields: map[string]*structpb.Value{
									runtime.RequestMethodAttr.String(): {
										Kind: &structpb.Value_StringValue{
											StringValue: "GET",
										},
									},
								},
							},
						},
						Request: &svcext_procv3.ProcessingRequest_RequestHeaders{
							RequestHeaders: &svcext_procv3.HttpHeaders{
								Headers: &corev3.HeaderMap{
									Headers: []*corev3.HeaderValue{
										{
											Key:      ":method",
											RawValue: []byte(""),
										},
										{
											Key:      ":authority",
											RawValue: []byte("localhost"),
										},
									},
								},
							},
						},
					},
					wantResp: &svcext_procv3.ProcessingResponse{
						Response: &svcext_procv3.ProcessingResponse_RequestHeaders{
							RequestHeaders: &svcext_procv3.HeadersResponse{
								Response: &svcext_procv3.CommonResponse{
									Status: svcext_procv3.CommonResponse_CONTINUE,
									HeaderMutation: &svcext_procv3.HeaderMutation{
										SetHeaders: []*corev3.HeaderValueOption{
											{
												Header: &corev3.HeaderValue{
													Key:      "content-length",
													RawValue: []byte("0"),
												},
												AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
											},
										},
									},
									ClearRouteCache: true,
								},
							},
						},
						ModeOverride: &ext_procv3.ProcessingMode{
							RequestBodyMode: ext_procv3.ProcessingMode_BUFFERED,
						},
					},
				},
				{
					request: &svcext_procv3.ProcessingRequest{
						MetadataContext: &corev3.Metadata{
							FilterMetadata: map[string]*structpb.Struct{},
						},
						Attributes: map[string]*structpb.Struct{
							"envoy.filters.http.ext_proc": {
								Fields: map[string]*structpb.Value{
									runtime.RequestMethodAttr.String(): {
										Kind: &structpb.Value_StringValue{
											StringValue: "GET",
										},
									},
								},
							},
						},
						Request: &svcext_procv3.ProcessingRequest_RequestBody{
							RequestBody: &svcext_procv3.HttpBody{
								Body: []byte("hello"),
							},
						},
					},
					wantResp: &svcext_procv3.ProcessingResponse{
						Response: &svcext_procv3.ProcessingResponse_ImmediateResponse{
							ImmediateResponse: &svcext_procv3.ImmediateResponse{
								Status: &typev3.HttpStatus{
									Code: typev3.StatusCode_OK,
								},
								Headers: &svcext_procv3.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{
											Header: &corev3.HeaderValue{
												Key:      "content-length",
												RawValue: []byte("5"), // len("hello")
											},
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
										},
									},
								},
								Body: []byte("hello"),
							},
						},
					},
				},
			},
		},
		{
			name:        "env",
			scriptTxtar: "env.js",
			steps: []step{
				{
					request: &svcext_procv3.ProcessingRequest{
						MetadataContext: &corev3.Metadata{
							FilterMetadata: map[string]*structpb.Struct{},
						},
						Attributes: map[string]*structpb.Struct{
							"envoy.filters.http.ext_proc": {
								Fields: map[string]*structpb.Value{
									runtime.RequestMethodAttr.String(): {
										Kind: &structpb.Value_StringValue{
											StringValue: "GET",
										},
									},
								},
							},
						},
						Request: &svcext_procv3.ProcessingRequest_RequestHeaders{
							RequestHeaders: &svcext_procv3.HttpHeaders{
								Headers: &corev3.HeaderMap{
									Headers: []*corev3.HeaderValue{
										{
											Key:      ":method",
											RawValue: []byte(""),
										},
										{
											Key:      ":authority",
											RawValue: []byte("localhost"),
										},
									},
								},
							},
						},
					},
					wantResp: &svcext_procv3.ProcessingResponse{
						Response: &svcext_procv3.ProcessingResponse_ImmediateResponse{
							ImmediateResponse: &svcext_procv3.ImmediateResponse{
								Status: &typev3.HttpStatus{
									Code: typev3.StatusCode_OK,
								},
								Headers: &svcext_procv3.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{
											Header: &corev3.HeaderValue{
												Key:      "content-length",
												RawValue: []byte("7"), // len("v1alpha")
											},
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
										},
									},
								},
								Body: []byte("v1alpha"),
							},
						},
					},
				},
			},
		},
		{
			name:        "fetch",
			scriptTxtar: "fetch.js",
			steps: []step{
				{
					request: &svcext_procv3.ProcessingRequest{
						MetadataContext: &corev3.Metadata{
							FilterMetadata: map[string]*structpb.Struct{},
						},
						Attributes: map[string]*structpb.Struct{
							"envoy.filters.http.ext_proc": {
								Fields: map[string]*structpb.Value{
									runtime.RequestMethodAttr.String(): {
										Kind: &structpb.Value_StringValue{
											StringValue: "GET",
										},
									},
								},
							},
						},
						Request: &svcext_procv3.ProcessingRequest_RequestHeaders{
							RequestHeaders: &svcext_procv3.HttpHeaders{
								Headers: &corev3.HeaderMap{
									Headers: []*corev3.HeaderValue{
										{
											Key:      ":method",
											RawValue: []byte(""),
										},
										{
											Key:      ":authority",
											RawValue: []byte("localhost"),
										},
									},
								},
							},
						},
					},
					wantResp: &svcext_procv3.ProcessingResponse{
						Response: &svcext_procv3.ProcessingResponse_RequestHeaders{
							RequestHeaders: &svcext_procv3.HeadersResponse{
								Response: &svcext_procv3.CommonResponse{
									Status: svcext_procv3.CommonResponse_CONTINUE,
									HeaderMutation: &svcext_procv3.HeaderMutation{
										SetHeaders: []*corev3.HeaderValueOption{
											{
												Header: &corev3.HeaderValue{
													Key:      "content-length",
													RawValue: []byte("0"),
												},
												AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
											},
										},
									},
									ClearRouteCache: true,
								},
							},
						},
						ModeOverride: &ext_procv3.ProcessingMode{
							RequestBodyMode: ext_procv3.ProcessingMode_BUFFERED,
						},
					},
				},
				{
					request: &svcext_procv3.ProcessingRequest{
						MetadataContext: &corev3.Metadata{
							FilterMetadata: map[string]*structpb.Struct{},
						},
						Attributes: map[string]*structpb.Struct{
							"envoy.filters.http.ext_proc": {
								Fields: map[string]*structpb.Value{
									runtime.RequestMethodAttr.String(): {
										Kind: &structpb.Value_StringValue{
											StringValue: "GET",
										},
									},
								},
							},
						},
						Request: &svcext_procv3.ProcessingRequest_RequestBody{
							RequestBody: &svcext_procv3.HttpBody{
								Body: []byte(fmt.Sprintf(`{"url": "%s/echo", "content": "foobar"}`, fakeSrv.URL)),
							},
						},
					},
					wantResp: &svcext_procv3.ProcessingResponse{
						Response: &svcext_procv3.ProcessingResponse_ImmediateResponse{
							ImmediateResponse: &svcext_procv3.ImmediateResponse{
								Status: &typev3.HttpStatus{
									Code: typev3.StatusCode_OK,
								},
								Headers: &svcext_procv3.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{
											Header: &corev3.HeaderValue{
												Key:      "content-length",
												RawValue: []byte("6"), // len("foobar")
											},
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
										},
									},
								},
								Body: []byte("foobar"),
							},
						},
					},
				},
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			i := slices.IndexFunc(ar.Files, func(f txtar.File) bool {
				if f.Name == tc.scriptTxtar {
					return true
				}
				return false
			})
			if i == -1 {
				t.Fatalf("could not find script %q", tc.scriptTxtar)
			}
			// Write the script to a temporary file.
			tmpFile, err := os.CreateTemp(t.TempDir(), "script-*.js")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpFile.Name())
			if _, err := tmpFile.Write(ar.Files[i].Data); err != nil {
				t.Fatal(err)
			}
			if err := tmpFile.Close(); err != nil {
				t.Fatal(err)
			}

			outPath := tmpFile.Name() + ".wasm"
			// Run apoxy-js to compile the script.
			out, err := exec.Command(
				"apoxy-js",
				tmpFile.Name(),
				"-o", outPath,
			).CombinedOutput()
			if err != nil {
				t.Fatalf("apoxy-js failed: %v\n%s", err, out)
			}
			m := newMetadata(tc.scriptTxtar)

			// Start the server.
			ls, err := net.Listen("tcp", fmt.Sprintf(":0"))
			if err != nil {
				t.Fatal(err)
			}
			defer ls.Close()
			srv := grpc.NewServer()
			epSrv := NewServer(manifest.NewLocalPathProvider(map[string]string{
				tc.scriptTxtar: outPath,
			}))
			epSrv.Register(srv)
			go srv.Serve(ls)
			defer srv.Stop()

			conn, err := grpc.NewClient(
				ls.Addr().String(),
				grpc.WithTransportCredentials(
					insecure.NewCredentials(),
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			c := svcext_procv3.NewExternalProcessorClient(conn)
			stream, err := c.Process(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			// Run the test steps.
			for i, step := range tc.steps {
				step.request.MetadataContext.FilterMetadata[runtime.ApoxyMetadataNamespace] = m
				// Send the request.
				if stream.Send(step.request); err != nil {
					t.Fatal(err)
				}

				// Receive the response.
				resp, err := stream.Recv()
				if step.wantErr != nil {
					if err == nil {
						t.Fatalf("expected error %v, got nil", step.wantErr)
					}
					if diff := cmp.Diff(step.wantErr.Error(), err.Error()); diff != "" {
						t.Fatalf("unexpected error (-got +want):\n%s", diff)
					}
					continue
				} else if step.wantEOF {
					if err != io.EOF {
						t.Fatalf("expected EOF, got %v", err)
					}
					continue
				} else if err != nil {
					t.Fatalf("unexpected receive error: %v", err)
				}
				if diff := cmp.Diff(step.wantResp, resp, protocmp.Transform()); diff != "" {
					t.Fatalf("step %d: unexpected response (-want +got):\n%s", i, diff)
				}
			}
		})
	}
}
