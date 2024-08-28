package websocket

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/buraksezer/olric"
	"github.com/coder/websocket"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/kvstore"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

type router struct {
	dm olric.DMap
}

func NewRouter(store *kvstore.Store) (*router, error) {
	dm, err := store.NewDMap("_apoxy_websocket_router")
	if err != nil {
		return nil, fmt.Errorf("failed to create DMap: %v", err)
	}
	return &router{dm: dm}, nil
}

func (r *router) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()

	return srv.ListenAndServe()
}

func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	downstreamConn, err := websocket.Accept(w, req, &websocket.AcceptOptions{})
	if err != nil {
		log.Errorf("failed to accept websocket connection: %v", err)
		return
	}
	defer downstreamConn.CloseNow()

	log.Infof("accepted websocket connection from %s for %s", req.RemoteAddr, req.Host)
	v, err := r.dm.Get(ctx, req.Host)
	if err != nil {
		log.Errorf("failed to get websocket connection for %s: %v", req.Host, err)
		downstreamConn.Close(websocket.StatusInternalError, "no websocket target")
		return
	}
	target, err := v.String()
	if err != nil {
		log.Errorf("failed to convert websocket connection for %s: %v", req.Host, err)
		downstreamConn.Close(websocket.StatusInternalError, "no websocket target")
		return
	}

	log.Infof("forwarding websocket connection from %s to %s", req.RemoteAddr, target)

	upstreamConn, resp, err := websocket.Dial(ctx, "ws://"+target, nil)
	if err != nil {
		log.Errorf("failed to dial websocket connection to %s: %v", target, err)
		downstreamConn.Close(websocket.StatusInternalError, "no websocket target")
		return
	}
	defer upstreamConn.CloseNow()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		log.Errorf("failed to upgrade websocket connection to %s: %v", target, resp.Status)
		downstreamConn.Close(websocket.StatusInternalError, "no websocket target")
		return
	}
	log.Infof("connected to websocket target %s", target)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()

		for {
			msgType, r, err := downstreamConn.Reader(ctx)
			if err != nil {
				if err != io.EOF {
					log.Errorf("failed to read from downstream connection: %v", err)
				}
				break
			}
			w, err := upstreamConn.Writer(ctx, msgType)
			if err != nil {
				log.Errorf("failed to write to upstream connection: %v", err)
				break
			}

			_, err = io.Copy(w, r)
			if err != nil {
				log.Errorf("failed to write to upstream connection: %v", err)
				break
			}
			w.Close()
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel()

		for {
			msgType, r, err := upstreamConn.Reader(ctx)
			if err != nil {
				if err != io.EOF {
					log.Errorf("failed to read from upstream connection: %v", err)
				}
				break
			}
			w, err := downstreamConn.Writer(ctx, msgType)
			if err != nil {
				log.Errorf("failed to write to downstream connection: %v", err)
				break
			}

			_, err = io.Copy(w, r)
			if err != nil {
				log.Errorf("failed to write to downstream connection: %v", err)
				break
			}
			w.Close()
		}
	}()
	wg.Wait()

	log.Infof("closing websocket connection from %s to %s", req.RemoteAddr, target)

	downstreamConn.Close(websocket.StatusNormalClosure, "connection closed")
}
