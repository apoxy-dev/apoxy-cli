package websocket

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/buraksezer/olric"
	"github.com/coder/websocket"

	"github.com/apoxy-dev/apoxy/pkg/backplane/kvstore"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

type router struct {
	dm     olric.DMap
	pubsub *olric.PubSub
}

func NewRouter(store *kvstore.Store) (*router, error) {
	dm, err := store.NewDMap("_apoxy_websocket_router")
	if err != nil {
		return nil, fmt.Errorf("failed to create DMap: %v", err)
	}
	ps, err := store.NewPubSub()
	if err != nil {
		return nil, fmt.Errorf("failed to create PubSub: %v", err)
	}
	return &router{
		dm:     dm,
		pubsub: ps,
	}, nil
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

func (r *router) awaitTarget(ctx context.Context, host string) (string, error) {
	sub := r.pubsub.PSubscribe(ctx, kvstore.PubSubChannel+":"+host)
	defer sub.Close()

	select {
	case m := <-sub.Channel():
		return m.Payload, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
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

	// Validate host: Must have at least two dot.
	if strings.Count(req.Host, ".") < 2 {
		log.Errorf("invalid host: %s", req.Host)
		downstreamConn.Close(websocket.StatusPolicyViolation, "invalid host")
		return
	}
	host := req.Host

	log.Infof("accepted websocket connection from %s for %s", req.RemoteAddr, host)

	target, err := r.awaitTarget(ctx, host)
	if err != nil {
		log.Errorf("failed to get websocket connection for %s: %v", host, err)
		downstreamConn.Close(websocket.StatusInternalError, "no websocket target")
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
