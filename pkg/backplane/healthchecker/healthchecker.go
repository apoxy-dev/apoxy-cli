package healthchecker

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// HealthChecker is an interface for health checkers
// that can be used to check the health of a system
// or service.
type HealthChecker interface {
	Check(ctx context.Context) (bool, error)
}

// AggregatedHealthChecker is a health checker that
// aggregates the results of multiple health checkers.
// If any of the health checkers return an error or
// unhealthy status, the AggregatedHealthChecker will
type AggregatedHealthChecker struct {
	mu       sync.RWMutex
	checkers map[string]HealthChecker
}

// NewAggregatedHealthChecker creates a new AggregatedHealthChecker.
func NewAggregatedHealthChecker() *AggregatedHealthChecker {
	return &AggregatedHealthChecker{
		checkers: make(map[string]HealthChecker),
	}
}

// Register adds a new health checker to the AggregatedHealthChecker.
func (ahc *AggregatedHealthChecker) Register(name string, checker HealthChecker) {
	ahc.mu.Lock()
	defer ahc.mu.Unlock()
	ahc.checkers[name] = checker
}

// Unregister removes a health checker from the AggregatedHealthChecker.
func (ahc *AggregatedHealthChecker) Unregister(name string) {
	ahc.mu.Lock()
	defer ahc.mu.Unlock()
	delete(ahc.checkers, name)
}

// ServeHTTP implements the http.Handler interface for the
// AggregatedHealthChecker.
func (ahc *AggregatedHealthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ahc.mu.RLock()
	checkers := make(map[string]HealthChecker, len(ahc.checkers))
	for name, checker := range ahc.checkers {
		checkers[name] = checker
	}
	ahc.mu.RUnlock()

	for name, checker := range checkers {
		healthy, err := checker.Check(ctx)
		if err != nil || !healthy {
			log.Errorf("Health check failed for %s: %v", name, err)
			http.Error(w, "Service Unhealthy", http.StatusServiceUnavailable)
			return
		}
	}
	fmt.Fprintln(w, "Service Healthy")
}

// Start starts the AggregatedHealthChecker on the specified port.
func (ahc *AggregatedHealthChecker) Start(ctx context.Context, port int) {
	mux := http.NewServeMux()
	mux.Handle("/readyz", ahc)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()
	server.ListenAndServe()
}
