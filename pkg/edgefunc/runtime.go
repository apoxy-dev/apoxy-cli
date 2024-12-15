package edgefunc

import (
	"context"
	"errors"
	"time"
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
	// Start request the runtime to start the execution of the function.
	// Cancelling the context will stop the runtime bookkeeping and all
	// of its children processes.
	Start(ctx context.Context, id string, esZipPath string) error

	// Stop request the runtime to stop the execution of the function.
	// The process may take some time to stop, so this method will return
	// immediately after sending the stop signal.
	// No-op if the runtime is already stopped.
	Stop(ctx context.Context, id string) error

	// Status returns the current status of the runtime.
	Status(ctx context.Context, id string) (Status, error)

	// List returns a list of all functions running in the runtime.
	List(ctx context.Context) ([]Status, error)
}
