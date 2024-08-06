package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/temporal"
	tworker "go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
	"github.com/apoxy-dev/apoxy-cli/rest"
)

const (
	EdgeFunctionIngestQueue = "EDGE_FUNC_INGEST_TASK_QUEUE"
)

const (
	InvalidInputError = "InvalidInputError"
)

type EdgeFunctionIngestParams struct {
	Obj *v1alpha1.EdgeFunction
}

type EdgeFunctionIngestResult struct {
	AssetFilePath      string
	AssetFileCreatedAt metav1.Time
	Err                string
}

// WorkflowID returns a unique identifier for the Edge Function ingest workflow.
// Each workflow is uniquely identified by the Edge Function name and its resource version.
func WorkflowID(o *v1alpha1.EdgeFunction) (string, error) {
	bs, err := json.Marshal(o.Spec.Code)
	if err != nil {
		return "", fmt.Errorf("failed to marshal EdgeFunction code spec: %w", err)
	}
	h := sha256.New()
	h.Write(bs)
	return o.Name + "@sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// RegisterWorkflows registers Edge Function workflows with the Temporal worker.
func RegisterWorkflows(w tworker.Worker) {
	w.RegisterWorkflow(EdgeFunctionIngestWorkflow)
}

// EdgeFunctionIngestWorkflow is a Temporal workflow that ingests Edge Functions.
// The function code is
func EdgeFunctionIngestWorkflow(ctx workflow.Context, in *EdgeFunctionIngestParams) error {
	opts := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute, // 10 min to download WASM file should be enough?
		// HeartbeatTimeout:    2 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:        time.Second,
			BackoffCoefficient:     2.0,
			MaximumInterval:        60 * time.Second,
			MaximumAttempts:        10,
			NonRetryableErrorTypes: []string{"FatalError"},
		},
	}
	ctx = workflow.WithActivityOptions(ctx, opts)
	log := tlog.With(workflow.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	so := &workflow.SessionOptions{
		CreationTimeout:  time.Minute,
		ExecutionTimeout: 5 * time.Minute,
	}
	sessCtx, err := workflow.CreateSession(ctx, so)
	if err != nil {
		return err
	}
	defer workflow.CompleteSession(sessCtx)

	var w *worker
	var res *EdgeFunctionIngestResult

	// Reflect if more than one pointer set.
	cv := reflect.ValueOf(in.Obj.Spec.Code)
	var fSet []reflect.Value
	for i := 0; i < cv.NumField(); i++ {
		if !cv.Field(i).IsNil() {
			fSet = append(fSet, cv.Field(i))
		}
	}
	switch len(fSet) {
	case 0:
		err = errors.New("Edge Function must have either WASM or JS source")
	case 1:
		switch fSet[0].Interface().(type) {
		case *v1alpha1.WasmSource:
			err = workflow.ExecuteActivity(sessCtx, w.DownloadWasmActivity, in).Get(sessCtx, &res)
			if err == nil {
				log.Info("Edge Function .wasm staged successfully", "WasmFilePath", res.AssetFilePath)
			}
		case *v1alpha1.JavaScriptSource:
			err = errors.New("JS source not supported yet")
		case *v1alpha1.GoPluginSource:
			err = workflow.ExecuteActivity(sessCtx, w.DownloadGoPluginActivity, in).Get(sessCtx, &res)
			if err == nil {
				log.Info("Edge Function Go plugin staged successfully", "GoPluginFilePath", res.AssetFilePath)
			}
		default:
			err = fmt.Errorf("Edge Function has invalid source type: %v", reflect.TypeOf(fSet[0].Interface()))
		}
	default:
		var names []string
		for _, f := range fSet {
			names = append(names, f.Type().Name())
		}
		err = fmt.Errorf("Edge Function must have either WASM or JS source, got %s", strings.Join(names, ", "))
	}
	if err != nil {
		log.Error("Download activity failed", "Error", err)
		res.Err = err.Error()
		goto Finalize
	}

	err = workflow.ExecuteActivity(sessCtx, w.StoreWasmActivity, in, res).Get(sessCtx, nil)
	if err != nil {
		log.Error("Store activity failed", "Error", err)
		res.Err = err.Error()
		goto Finalize
	}

Finalize:
	finErr := workflow.ExecuteActivity(sessCtx, w.FinalizeActivity, in, res).Get(ctx, nil)
	if finErr != nil {
		log.Error("Failed to finalize Edge Function ingest", "Error", finErr)
		return finErr
	}

	log.Info("Edge Function ingest completed successfully")
	return nil
}

// Worker implements Temporal Activities for Edge Functions Ingest queue.
type worker struct {
	a3y     versioned.Interface
	baseDir string
}

// NewWorker returns a new worker for Edge Functions Ingest queue.
func NewWorker(c *rest.APIClient, baseDir string) *worker {
	return &worker{
		a3y:     c,
		baseDir: baseDir,
	}
}

// RegisterActivities registers Edge Functions Ingest activities with
// the Temporal worker instance.
func (w *worker) RegisterActivities(tw tworker.Worker) {
	tw.RegisterActivity(w.DownloadWasmActivity)
	tw.RegisterActivity(w.StoreWasmActivity)
	tw.RegisterActivity(w.DownloadGoPluginActivity)
	tw.RegisterActivity(w.StoreGoPluginActivity)
	tw.RegisterActivity(w.FinalizeActivity)
}

func (w *worker) stagingDir(name, rid string) string {
	return filepath.Join(w.baseDir, "run", "ingest", "staging", name, rid)
}

func (w *worker) storeDir(name string) string {
	return filepath.Join(w.baseDir, "/run", "ingest", "store", name)
}

const (
	// MaxFileSize is the maximum size of the file that can be downloaded.
	MaxFileSize = 20 * 1024 * 1024 // 20MB
	// MaxErrorSize is the maximum size of the error message that can be returned.
	MaxErrorSize = 1024
)

func (w *worker) downloadFile(ctx context.Context, url, target string) error {
	c := http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Check if body contains error message
		// If so, return that error message
		var msg []byte
		if resp.ContentLength > MaxErrorSize {
			msg = []byte("Error message too large to display")
		} else {
			var err error
			msg, err = io.ReadAll(io.LimitReader(resp.Body, MaxErrorSize))
			if err != nil {
				msg = []byte("Failed to read error message")
			}
		}

		return fmt.Errorf("Failed to download file: %s (%s)", resp.Status, string(msg))
	}

	if resp.ContentLength > MaxFileSize {
		return fmt.Errorf("File size exceeds maximum allowed size: %d", resp.ContentLength)
	}

	tf, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(tf, io.LimitReader(resp.Body, MaxFileSize)); err != nil {
		return err
	}

	return nil
}

// DownloadWasmActivity downloads the Edge Function .wasm file.
func (w *worker) DownloadWasmActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*EdgeFunctionIngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	targetDir := w.stagingDir(wid, rid)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}

	wasmFile := filepath.Join(targetDir, "func.wasm")
	if err := w.downloadFile(ctx, in.Obj.Spec.Code.WasmSource.URL, wasmFile); err != nil {
		log.Error("Failed to download WASM file", "Error", err)
		return nil, err
	}

	stat, err := os.Stat(wasmFile)
	if err != nil {
		log.Error("Failed to stat WASM file", "Error", err)
		return nil, err
	}

	return &EdgeFunctionIngestResult{
		AssetFilePath:      wasmFile,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

// StoreWasmActivity stores the Edge Function .wasm file in the object store.
func (w *worker) StoreWasmActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	inResult *EdgeFunctionIngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Storing Edge Function .wasm file in object store")

	wid := activity.GetInfo(ctx).WorkflowExecution.ID

	targetDir := w.storeDir(wid)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return err
	}

	targetFile := filepath.Join(targetDir, "func.wasm")
	// TODO(dilyevsky): Use object store API to store the file.
	// For now, just link the file to the target directory.
	if err := os.Rename(inResult.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

// DownloadGoPluginActivity downloads the Edge Function Go plugin .so file and stores it in the staging directory.
func (w *worker) DownloadGoPluginActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*EdgeFunctionIngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	log.Info("Downloading Edge Function Go plugin .so file", "URL", in.Obj.Spec.Code.GoPluginSource.URL)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	targetDir := w.stagingDir(wid, rid)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}

	soFile := filepath.Join(targetDir, "func.so")
	if err := w.downloadFile(ctx, in.Obj.Spec.Code.GoPluginSource.URL, soFile); err != nil {
		log.Error("Failed to download .so file", "Error", err)
		return nil, err
	}

	stat, err := os.Stat(soFile)
	if err != nil {
		log.Error("Failed to stat .so file", "Error", err)
		return nil, err
	}

	return &EdgeFunctionIngestResult{
		AssetFilePath:      soFile,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

// StoreGoPluginActivity stores the Edge Function Go plugin .so file in the object store.
func (w *worker) StoreGoPluginActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	inResult *EdgeFunctionIngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Storing Edge Function .so file in object store")

	wid := activity.GetInfo(ctx).WorkflowExecution.ID

	targetDir := w.storeDir(wid)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return err
	}

	targetFile := filepath.Join(targetDir, "func.so")
	// TODO(dilyevsky): Use object store API to store the file.
	// For now, just link the file to the target directory.
	if err := os.Rename(inResult.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

// FinalizeActivity finalizes the Edge Function ingest workflow.
// This activity is responsible for updating the Edge Function status.
func (w *worker) FinalizeActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	inResult *EdgeFunctionIngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Finalizing Edge Function ingest", "Error", inResult.Err)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		log.Info("Updating Edge Function status")

		f, err := w.a3y.ExtensionsV1alpha1().EdgeFunctions().Get(ctx, in.Obj.Name, metav1.GetOptions{})
		if err != nil {
			log.Error("Failed to get Edge Function", "Error", err)
			return err
		}

		if inResult.Err != "" {
			// TODO(dilyevsky): Check history and rollback to previous version if needed.
			f.Status.Phase = v1alpha1.EdgeFunctionPhaseFailed
			f.Status.Message = inResult.Err
		} else {
			f.Status.Phase = v1alpha1.EdgeFunctionPhaseReady
			// Prepend the revision to the list of revisions.
			rev := v1alpha1.EdgeFunctionRevision{
				Ref:       activity.GetInfo(ctx).WorkflowExecution.ID,
				CreatedAt: inResult.AssetFileCreatedAt,
			}
			f.Status.Revisions = append([]v1alpha1.EdgeFunctionRevision{rev}, f.Status.Revisions...)
		}

		if _, err := w.a3y.ExtensionsV1alpha1().EdgeFunctions().UpdateStatus(ctx, f, metav1.UpdateOptions{}); err != nil {
			log.Error("Failed to update Edge Function status", "Error", err)
			return err
		}

		return nil
	})
}

// ListenAndServeWasm starts an HTTP server to serve the Edge Function .wasm file.
func (w *worker) ListenAndServeWasm(host string, port int) error {
	mux := http.NewServeMux()
	mux.Handle("/wasm/", w)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Infof("Listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (w *worker) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	ss := strings.Split(req.URL.Path, "/")
	name := ss[len(ss)-1]
	if name == "" {
		http.Error(wr, "Name is required", http.StatusBadRequest)
		return
	}
	p := w.storeDir(name) + "/func.wasm"
	if _, err := os.Stat(p); err != nil {
		http.Error(wr, "File not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(wr, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	wr.Header().Set("Content-Type", "application/octet-stream")

	if _, err := io.Copy(wr, f); err != nil {
		http.Error(wr, "Failed to copy file", http.StatusInternalServerError)
		return
	}

	wr.WriteHeader(http.StatusOK)
}
