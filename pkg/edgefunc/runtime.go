package edgefunc

import (
	"context"
	"errors"
	"time"

	"github.com/coredns/coredns/plugin"
)

const (
	DomainSuffix = "apoxy.local"
)

var (
	ErrAlreadyExists = errors.New("function already exists")
	ErrNotFound      = errors.New("function not found")
)

type State string

const (
	StateCreated State = "Created"
	StateRunning State = "Running"
	StatePaused  State = "Paused"
	StateStopped State = "Stopped"
	StateUnknown State = "Unknown"
)

type Status struct {
	ID        string    `json:"id"`
	State     State     `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
}

type Runtime interface {
	// Exec creates a new function execution.
	Exec(ctx context.Context, id string, esZipPath string) error

	// StopExec stops the execution of the function.
	// The process may take some time to stop, so this method will return
	// immediately after sending the stop signal.
	// No-op if the runtime is already stopped.
	StopExec(ctx context.Context, id string) error

	// DeleteExec deletes the function execution.
	DeleteExec(ctx context.Context, id string) error

	// ExecStatus returns the current status of the runtime.
	ExecStatus(ctx context.Context, id string) (Status, error)

	// ListExecs returns a list of all function executions.
	ListExecs(ctx context.Context) ([]Status, error)

	// Resolver implements the dns.Plugin interface - returns a dns.Handler
	// to resolve edge function names. Must call next to continue the DNS
	// resolution.
	Resolver(next plugin.Handler) plugin.Handler
}
