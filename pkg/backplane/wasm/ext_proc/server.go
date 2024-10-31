package ext_proc

import (
	"fmt"

	svcext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/wasm/runtime"
)

// Server implements ext_procv3.ExternalProcessorServer.
type Server struct {
	manifestProvider manifest.Provider
}

// NewServer creates a new External Processor server.
func NewServer(mp manifest.Provider) *Server {
	return &Server{
		manifestProvider: mp,
	}
}

// Register registers the External Processor server with the gRPC server.
func (s *Server) Register(srv *grpc.Server) {
	svcext_procv3.RegisterExternalProcessorServer(srv, s)
}

// Process implements ext_proc.ExternalProcessorServer.
func (s *Server) Process(srv svcext_procv3.ExternalProcessor_ProcessServer) error {
	ctx := srv.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("missing metadata")
	}
	host := md.Get(":authority")
	if len(host) == 0 {
		return fmt.Errorf("missing host")
	}
	m, err := s.manifestProvider.Get(ctx, host[0])
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	curExec, err := runtime.StartExec(ctx, *m)
	if err != nil {
		fmt.Printf("Error starting runtime: %v\n", err)
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fmt.Printf("Processing state: %T\n", curExec)
		nextExec, err := curExec.Next(ctx, srv)
		if err != nil {
			fmt.Printf("Error processing request: %v\n", err)
			return err
		}
		if nextExec == nil {
			fmt.Printf("Finished processing request\n")
			return nil
		}
		curExec = nextExec
	}
}
