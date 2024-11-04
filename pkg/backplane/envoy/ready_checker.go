package envoy

import (
	"context"
	"fmt"
	"io"
	"net/http"

	adminv3 "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

type Listener struct {
	Name    string
	Address corev3.Address
}

type readyChecker struct {
	port      int
	listeners []*Listener
	adminHost string
}

func (hc *readyChecker) checkListeners(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("http://%s/listeners?format=json", hc.adminHost))
	if err != nil {
		http.Error(w, "Failed to get listeners from admin endpoint", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	adminListeners := adminv3.Listeners{}
	if err := protojson.Unmarshal(body, &adminListeners); err != nil {
		http.Error(w, "Failed to unmarshal listeners", http.StatusInternalServerError)
		return
	}

	for _, l := range hc.listeners {
		found := false
		for _, ls := range adminListeners.ListenerStatuses {
			nameMatch := l.Name == "" || l.Name == ls.Name
			if nameMatch &&
				l.Address.GetSocketAddress().GetPortValue() == ls.LocalAddress.GetSocketAddress().GetPortValue() &&
				l.Address.GetSocketAddress().GetProtocol() == ls.LocalAddress.GetSocketAddress().GetProtocol() {
				found = true
				break
			}
			log.Debugf("Listener not matched: name=%s, port=%d, protocol=%s",
				ls.Name,
				ls.LocalAddress.GetSocketAddress().GetPortValue(),
				ls.LocalAddress.GetSocketAddress().GetProtocol())
		}
		if !found {
			log.Infof("Listener not found: name=%s, port=%d, protocol=%s",
				l.Name,
				l.Address.GetSocketAddress().GetPortValue(),
				l.Address.GetSocketAddress().GetProtocol())
			http.Error(w, "Listener not found: "+l.Name, http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("All listeners are present"))
}

func (hc *readyChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hc.checkListeners(w, r)
}

func (hc *readyChecker) run(ctx context.Context) {
	mux := http.NewServeMux()
	mux.Handle("/ready", hc)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", hc.port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			log.Errorf("Failed to shutdown server: %v", err)
		}
	}()

	log.Infof("Starting health checker on port %d", hc.port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Errorf("Server error: %v", err)
	}
}
