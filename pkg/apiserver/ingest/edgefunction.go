package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.temporal.io/sdk/activity"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/temporal"
	tworker "go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"

	"github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
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

type IngestResult struct {
	AssetFilePath      string
	AssetFileCreatedAt metav1.Time
	Err                string
}

// WorkflowID returns a unique identifier for the Edge Function ingest workflow.
// Each workflow is uniquely identified by the Edge Function name and its code configuration.
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
			BackoffCoefficient:     5.0,
			MaximumInterval:        60 * time.Second,
			MaximumAttempts:        3,
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
	var res IngestResult

	// Reflect if more than one pointer set.
	cv := reflect.ValueOf(in.Obj.Spec.Code)
	var fSet []reflect.Value
	for _, f := range reflect.VisibleFields(cv.Type()) {
		if f.Anonymous { // Skip embedded fields.
			continue
		}
		fv := cv.FieldByIndex(f.Index)
		if fv.Kind() == reflect.Ptr && !fv.IsNil() {
			fSet = append(fSet, fv)
		}
	}
	switch len(fSet) {
	case 0:
		err = errors.New("Edge Function must have either WASM or JS source")
	case 1:
		switch fSet[0].Interface().(type) {
		case *v1alpha1.WasmSource:
			log.Info("EdgeFunction ingest started", "Source", "WASM")
			err = workflow.ExecuteActivity(sessCtx, w.DownloadWasmActivity, in).Get(sessCtx, &res)
			if err != nil {
				log.Error("Download activity failed", "Error", err)
				goto Finalize
			}

			log.Info("EdgeFunction .wasm staged successfully", "WasmFilePath", res.AssetFilePath)

			err = workflow.ExecuteActivity(sessCtx, w.StoreWasmActivity, in, res).Get(sessCtx, nil)
			if err != nil {
				log.Error("Store activity failed", "Error", err)
				goto Finalize
			}
		case *v1alpha1.JavaScriptSource:
			log.Info("EdgeFunction ingest started", "Source", "JS")
			if err = workflow.ExecuteActivity(sessCtx, w.DownloadJsActivity, in).Get(sessCtx, &res); err != nil {
				log.Error("Failed to download JS source", "Error", err)
				goto Finalize
			}

			log.Info("EdgeFunction .eszip staged successfully", "EsZipPath", res.AssetFilePath)

			if err = workflow.ExecuteActivity(sessCtx, w.BundleJsActivity, in, res).Get(sessCtx, &res); err != nil {
				log.Error("Failed to bundle JS source", "Error", err)
				goto Finalize
			}

			if err = workflow.ExecuteActivity(sessCtx, w.StoreEsZipActivity, in, res).Get(sessCtx, nil); err != nil {
				log.Error("Store activity failed", "Error", err)
				goto Finalize
			}
		case *v1alpha1.GoPluginSource:
			log.Info("EdgeFunction ingest started", "Source", "GoPlugin")
			err = workflow.ExecuteActivity(sessCtx, w.DownloadGoPluginActivity, in).Get(sessCtx, &res)
			if err != nil {
				log.Error("Download activity failed", "Error", err)
				goto Finalize
			}

			log.Info("EdgeFunction Go plugin staged successfully", "GoPluginFilePath", res.AssetFilePath)
			err = workflow.ExecuteActivity(sessCtx, w.StoreGoPluginActivity, in, res).Get(sessCtx, nil)
			if err != nil {
				log.Error("Store activity failed", "Error", err)
				goto Finalize
			}
		default:
			err = fmt.Errorf("Edge Function has invalid source type: %v", reflect.TypeOf(fSet[0].Interface()))
		}
	default:
		var names []string
		for _, f := range fSet {
			names = append(names, f.Type().Name())
		}
		err = fmt.Errorf("EdgeFunction must have either WASM or JS source, got %s", strings.Join(names, ", "))
	}

Finalize:
	var appErr *temporal.ApplicationError
	if errors.As(err, &appErr) {
		res.Err = appErr.Error()
	}
	finErr := workflow.ExecuteActivity(sessCtx, w.FinalizeActivity, in, &res).Get(ctx, nil)
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
func NewWorker(c versioned.Interface, baseDir string) *worker {
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
	tw.RegisterActivity(w.DownloadJsActivity)
	tw.RegisterActivity(w.BundleJsActivity)
	tw.RegisterActivity(w.StoreEsZipActivity)
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
	MaxFileSize = 50 * 1024 * 1024 // 50MB
	// MaxErrorSize is the maximum size of the error message that can be returned.
	MaxErrorSize = 1024
)

func (w *worker) downloadFile(ctx context.Context, url, target string) (os.FileInfo, error) {
	c := http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
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

		return nil, fmt.Errorf("Failed to download file: %s (%s)", resp.Status, string(msg))
	}

	if resp.ContentLength > MaxFileSize {
		return nil, fmt.Errorf("File size exceeds maximum allowed size: %d", resp.ContentLength)
	}

	tf, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(tf, io.LimitReader(resp.Body, MaxFileSize)); err != nil {
		return nil, err
	}

	return tf.Stat()
}

// DownloadWasmActivity downloads the Edge Function .wasm file.
func (w *worker) DownloadWasmActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	d := w.stagingDir(wid, rid)

	if err := os.MkdirAll(d, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}

	wasmFile := filepath.Join(d, "func.wasm")
	stat, err := w.downloadFile(ctx, in.Obj.Spec.Code.WasmSource.URL, wasmFile)
	if err != nil {
		log.Error("Failed to download WASM file", "Error", err)
		return nil, err
	}

	return &IngestResult{
		AssetFilePath:      wasmFile,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

// StoreWasmActivity stores the Edge Function .wasm file in the object store.
func (w *worker) StoreWasmActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
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
	if err := os.Rename(res.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

func (w *worker) pullOCIImage(
	ctx context.Context,
	log tlog.Logger,
	targetPath string,
	ociRef *v1alpha1.OCIImageRef,
) (os.FileInfo, error) {
	log.Info("Pulling OCI image", "Ref", ociRef)

	fs, err := file.New(filepath.Dir(targetPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create file system: %w", err)
	}
	defer fs.Close()

	repo, err := remote.NewRepository(ociRef.Repo)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	var credsFunc auth.CredentialFunc
	if ociRef.Credentials != nil {
		pwd := make([]byte, base64.StdEncoding.DecodedLen(len(ociRef.Credentials.PasswordData)))
		n, err := base64.StdEncoding.Decode(pwd, ociRef.Credentials.PasswordData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode password: %w", err)
		}
		pwd = pwd[:n]

		credsFunc = auth.StaticCredential(
			repo.Reference.Registry,
			auth.Credential{
				Username: ociRef.Credentials.Username,
				Password: string(pwd),
			},
		)
	} else if ociRef.CredentialsRef != nil {
		// TODO(dsky): Implement credentials ref.
	} else {
		log.Debug("No credentials provided for OCI registry")
	}

	repo.Client = &auth.Client{
		Client:     orasretry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: credsFunc,
	}

	opts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{
			PreCopy: func(ctx context.Context, desc ocispecv1.Descriptor) error {
				log.Debug("Pre-copy", "MediaType", desc.MediaType)
				if desc.MediaType == ocispecv1.MediaTypeImageManifest ||
					desc.MediaType == v1alpha1.ImageLayerMediaType {
					return nil
				}
				return oras.SkipNode
			},
		},
	}
	opts.WithTargetPlatform(&ocispecv1.Platform{
		Architecture: runtime.GOARCH,
		OS:           "linux",
	})
	manifest, err := oras.Copy(ctx, repo, ociRef.Tag, fs, "", opts)
	if err != nil {
		return nil, fmt.Errorf("failed to pull OCI image: %w", err)
	}

	log.Info("OCI image pulled", "Digest", manifest.Digest.String())

	if manifest.MediaType != ocispecv1.MediaTypeImageManifest {
		return nil, fmt.Errorf("unexpected manifest media type: %s", manifest.MediaType)
	}

	manifestblob, err := content.FetchAll(ctx, fs, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest blob: %w", err)
	}
	var imgManifest ocispecv1.Manifest
	if err := json.Unmarshal(manifestblob, &imgManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(imgManifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers found in the manifest")
	}

	// See: https://oras.land/docs/concepts/artifact#determining-the-artifact-type
	if imgManifest.ArtifactType != v1alpha1.ImageConfigMediaType ||
		imgManifest.Config.MediaType != v1alpha1.ImageConfigMediaType {
		for _, layer := range imgManifest.Layers {
			if layer.MediaType == v1alpha1.ImageLayerMediaType {
				log.Info("Found image layer", "Digest", layer.Digest.String())
				tar, err := content.FetchAll(ctx, fs, layer)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch layer: %w", err)
				}

				if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
					return nil, fmt.Errorf("failed to create target directory: %w", err)
				}
				if err := os.WriteFile(targetPath, tar, 0644); err != nil {
					return nil, fmt.Errorf("failed to write file: %w", err)
				}

				return os.Stat(targetPath)
			}
		}
	}

	return nil, fmt.Errorf("no image layer found in the manifest")
}

// DownloadGoPluginActivity downloads the Edge Function Go plugin .so file and stores it in the staging directory.
func (w *worker) DownloadGoPluginActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	log.Info("Downloading Edge Function Go plugin .so file", "URL", in.Obj.Spec.Code.GoPluginSource.URL)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	targetDir := w.stagingDir(wid, rid)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}

	if in.Obj.Spec.Code.GoPluginSource.OCI != nil && in.Obj.Spec.Code.GoPluginSource.URL != nil {
		return nil, fmt.Errorf("both OCI and URL sources are specified")
	}

	soFile := filepath.Join(targetDir, "func.so")
	var stat os.FileInfo
	var err error
	if in.Obj.Spec.Code.GoPluginSource.OCI != nil {
		stat, err = w.pullOCIImage(ctx, log, soFile, in.Obj.Spec.Code.GoPluginSource.OCI)
		if err != nil {
			log.Error("Failed to pull OCI image", "Error", err)
			return nil, err
		}
	} else if in.Obj.Spec.Code.GoPluginSource.URL != nil {
		stat, err = w.downloadFile(ctx, *in.Obj.Spec.Code.GoPluginSource.URL, soFile)
		if err != nil {
			log.Error("Failed to download .so file", "Error", err)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no source specified")
	}

	return &IngestResult{
		AssetFilePath:      soFile,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

// StoreGoPluginActivity stores the Edge Function Go plugin .so file in the object store.
func (w *worker) StoreGoPluginActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	out *IngestResult,
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
	if err := os.Rename(out.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

func (w *worker) DownloadJsActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	rid := activity.GetInfo(ctx).WorkflowExecution.RunID

	jsDir := filepath.Join(w.stagingDir(wid, rid), "js")
	if err := os.MkdirAll(jsDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}
	stat, err := os.Stat(jsDir)
	if err != nil {
		log.Error("Failed to stat target directory", "Error", err)
		return nil, err
	}

	if in.Obj.Spec.Code.JsSource.Assets != nil {
		for _, f := range in.Obj.Spec.Code.JsSource.Assets.Files {
			targetFile := filepath.Join(jsDir, filepath.Clean(f.Path))
			if err := os.MkdirAll(filepath.Dir(targetFile), 0755); err != nil {
				log.Error("Failed to create target directory for asset", "Error", err)
				return nil, err
			}
			dstFile, err := os.Create(targetFile)
			if err != nil {
				log.Error("Failed to create js file", "Error", err)
				return nil, err
			}
			defer dstFile.Close()

			r := strings.NewReader(f.Content)
			if _, err := io.Copy(dstFile, r); err != nil {
				log.Error("Failed to copy file content", "Error", err)
				return nil, err
			}
		}
	} else if in.Obj.Spec.Code.JsSource.Git != nil {
		return nil, fmt.Errorf("Git source not supported yet")
	} else {
		return nil, fmt.Errorf("No source specified")
	}
	if err != nil {
		log.Error("Failed to download JS file", "Error", err)
		return nil, err
	}

	return &IngestResult{
		AssetFilePath:      jsDir,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

func (w *worker) BundleJsActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	rid := activity.GetInfo(ctx).WorkflowExecution.RunID

	d := w.stagingDir(wid, rid)
	binDir := filepath.Join(d, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		log.Error("Failed to create bin directory", "Error", err)
		return nil, err
	}
	esZip := filepath.Join(binDir, "bin.eszip")

	log.Info("Bundling JS files", "Directory", d)

	entry := filepath.Join(res.AssetFilePath, in.Obj.Spec.Code.JsSource.Entrypoint)
	log.Debug("Checking entrypoint exists", "Entry", entry)
	if _, err := os.Stat(entry); err != nil {
		log.Error("Entrypoint not found", "Error", err)
		return nil, err
	}
	cmd := exec.CommandContext(
		ctx,
		"edge-runtime", "bundle",
		"--entrypoint", entry,
		"--output", esZip,
	)

	log.Info("Running edge-runtime bundle", "Command", cmd.String())

	if out, err := cmd.CombinedOutput(); err != nil {
		log.Error("Failed to bundle JS files", "Error", err, "Output", string(out))
		return nil, temporal.NewNonRetryableApplicationError("Failed to bundle JS files", "", err)
	}

	stat, err := os.Stat(esZip)
	if err != nil {
		log.Error("Failed to find bundled eszip", "Error", err)
		return nil, err
	}

	return &IngestResult{
		AssetFilePath:      esZip,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

func (w *worker) StoreEsZipActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	wid := activity.GetInfo(ctx).WorkflowExecution.ID
	storeDir := w.storeDir(wid)
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return err
	}

	log.Info("Storing JS bundle", "Directory", storeDir)

	targetFile := filepath.Join(storeDir, "bin.eszip")
	// TODO(dilyevsky): Use object store API to store the file.
	// For now, just link the file to the target directory.
	if err := os.Rename(res.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

// This activity is responsible for updating the Edge Function status.
func (w *worker) FinalizeActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Finalizing Edge Function ingest", "Error", res.Err)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		log.Info("Updating Edge Function status")

		f, err := w.a3y.ExtensionsV1alpha1().EdgeFunctions().Get(ctx, in.Obj.Name, metav1.GetOptions{})
		if err != nil {
			log.Error("Failed to get Edge Function", "Error", err)
			return err
		}

		rev := v1alpha1.EdgeFunctionRevision{
			Ref:       activity.GetInfo(ctx).WorkflowExecution.ID,
			CreatedAt: res.AssetFileCreatedAt,
		}
		if res.Err != "" {
			rev.Conditions = append(f.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "Failed",
				Message:            res.Err,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})

			// If there is no live revision to use, the function is not ready.
			if f.Status.Live == "" {
				f.Status.Phase = v1alpha1.EdgeFunctionPhaseNotReady
				f.Status.Message = "No Ready revisions"
				if !hasCondition(f.Status.Conditions, "Ready", metav1.ConditionFalse) {
					f.Status.Conditions = append(f.Status.Conditions, metav1.Condition{
						Type:               "Ready",
						Status:             metav1.ConditionFalse,
						Reason:             "Failed",
						Message:            res.Err,
						LastTransitionTime: metav1.NewTime(time.Now()),
					})
				}
			} else {
				f.Status.Phase = v1alpha1.EdgeFunctionPhaseReady // Was Updating.
				if !hasCondition(f.Status.Conditions, "Ready", metav1.ConditionTrue) {
					f.Status.Conditions = append(f.Status.Conditions, metav1.Condition{
						Type:               "Ready",
						Status:             metav1.ConditionTrue,
						Reason:             "Ready",
						Message:            "Ready",
						LastTransitionTime: metav1.NewTime(time.Now()),
					})
				}
			}
		} else {
			f.Status.Phase = v1alpha1.EdgeFunctionPhaseReady
			if !hasCondition(f.Status.Conditions, "Ready", metav1.ConditionTrue) {
				f.Status.Conditions = append(f.Status.Conditions, metav1.Condition{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Ready",
					Message:            "Ready",
					LastTransitionTime: metav1.NewTime(time.Now()),
				})
			}

			if !hasCondition(rev.Conditions, "Ready", metav1.ConditionTrue) {
				rev.Conditions = append(rev.Conditions, metav1.Condition{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Ready",
					Message:            "Ready",
					LastTransitionTime: metav1.NewTime(time.Now()),
				})
			}
			if !hasCondition(rev.Conditions, "Live", metav1.ConditionTrue) {
				rev.Conditions = append(rev.Conditions, metav1.Condition{
					Type:               "Live",
					Status:             metav1.ConditionTrue,
					Reason:             "Live",
					Message:            "Revision is live",
					LastTransitionTime: metav1.NewTime(time.Now()),
				})
			}

			resetLiveRevision(f, rev.Ref)

			// Prepend the revision to the list of revisions.
			f.Status.Revisions = append([]v1alpha1.EdgeFunctionRevision{rev}, f.Status.Revisions...)
		}

		if _, err := w.a3y.ExtensionsV1alpha1().EdgeFunctions().UpdateStatus(ctx, f, metav1.UpdateOptions{}); err != nil {
			log.Error("Failed to update Edge Function status", "Error", err)
			return err
		}

		log.Info("Edge Function status updated successfully", "Phase", f.Status.Phase)

		return nil
	})
}

func resetLiveRevision(f *v1alpha1.EdgeFunction, liveRef string) {
	if f.Status.Live == liveRef {
		return
	}

	// Find the previous Live revision.
	prevIdx := slices.IndexFunc(f.Status.Revisions, func(r v1alpha1.EdgeFunctionRevision) bool {
		return r.Ref == f.Status.Live
	})
	if prevIdx == -1 {
		return
	}

	f.Status.Live = liveRef

	// Find existing Live condition and update it.
	liveIdx := slices.IndexFunc(f.Status.Revisions[prevIdx].Conditions, func(c metav1.Condition) bool {
		return c.Type == "Live"
	})
	if liveIdx != -1 {
		f.Status.Revisions[prevIdx].Conditions[liveIdx].Status = metav1.ConditionFalse
		f.Status.Revisions[prevIdx].Conditions[liveIdx].Message = "Revision is not live"
		f.Status.Revisions[prevIdx].Conditions[liveIdx].LastTransitionTime = metav1.NewTime(time.Now())
	} else {
		f.Status.Revisions[prevIdx].Conditions = append(f.Status.Revisions[prevIdx].Conditions,
			metav1.Condition{
				Type:               "Live",
				Status:             metav1.ConditionFalse,
				Reason:             "Live",
				Message:            "Revision is not live",
				LastTransitionTime: metav1.NewTime(time.Now()),
			},
		)
	}
}

func hasCondition(conditions []metav1.Condition, condType string, status metav1.ConditionStatus) bool {
	for _, c := range conditions {
		if c.Type == condType && c.Status == status {
			return true
		}
	}
	return false
}

// ListenAndServeEdgeFuncs starts an HTTP server to serve the Edge Function .wasm file.
func (w *worker) ListenAndServeEdgeFuncs(host string, port int) error {
	mux := http.NewServeMux()
	mux.Handle("/wasm/", w)
	mux.Handle("/go/", w)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Infof("Listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (w *worker) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Infof("Serving %s", req.URL.Path)
	path := filepath.Clean(strings.TrimLeft(req.URL.Path, "/"))
	ss := strings.Split(path, "/")
	if len(ss) != 2 {
		log.Errorf("Invalid path %s", path)
		http.Error(wr, "Invalid path", http.StatusBadRequest)
		return
	}
	t, name := ss[0], ss[1]
	if name == "" {
		log.Errorf("Name is required: %s", path)
		http.Error(wr, "Name is required", http.StatusBadRequest)
		return
	}
	var p string
	switch t {
	case "wasm":
		p = w.storeDir(name) + "/func.wasm"
	case "go":
		p = w.storeDir(name) + "/func.so"
	case "js":
		p = w.storeDir(name) + "/bin.eszip"
	default:
		log.Errorf("Invalid type %s", t)
		http.Error(wr, "Invalid type", http.StatusBadRequest)
		return
	}

	log.Infof("Serving edge function %s from %s", name, p)

	if _, err := os.Stat(p); err != nil {
		log.Errorf("Failed to stat %s", p)
		http.Error(wr, "File not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		log.Errorf("Failed to open %s for reading", p)
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
