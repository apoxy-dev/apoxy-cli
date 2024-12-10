package controllers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy-cli/pkg/edgefunc"
)

const (
	edgeFuncRevsOwnerIndex = "edgeFuncRevsOwner"
)

var _ reconcile.Reconciler = &EdgeFunctionReconciler{}

// EdgeFunctionReconciler reconciles a Proxy object.
type EdgeFunctionReconciler struct {
	client.Client

	apiserverHost string
	wasmStore     manifest.Store
	goStoreDir    string
	jsStoreDir    string
	edgeRuntime   edgefunc.Runtime

	mu        sync.Mutex
	edgeFuncs map[string]*v1alpha1.EdgeFunctionRevision
}

// NewEdgeFuncReconciler returns a new reconcile.Reconciler.
func NewEdgeFuncReconciler(
	c client.Client,
	apiserverHost string,
	wasmStore manifest.Store,
	goStoreDir string,
	jsStoreDir string,
) *EdgeFunctionReconciler {
	return &EdgeFunctionReconciler{
		Client:        c,
		apiserverHost: apiserverHost,
		wasmStore:     wasmStore,
		goStoreDir:    goStoreDir,
		jsStoreDir:    jsStoreDir,

		edgeFuncs: make(map[string]*v1alpha1.EdgeFunctionRevision),
	}
}

func (r *EdgeFunctionReconciler) downloadFuncData(
	ctx context.Context,
	fnType string,
	ref string,
) ([]byte, error) {
	log := clog.FromContext(ctx)

	resp, err := http.Get(fmt.Sprintf("http://%s/%s/%s", r.apiserverHost, fnType, ref))
	if err != nil {
		return nil, fmt.Errorf("failed to download Wasm module: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download Wasm module: %s", resp.Status)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Wasm module: %w", err)
	}

	log.Info("Downloaded EdgeFunction module", "size", len(data), "type", fnType, "ref", ref)

	return data, nil
}

func hasReadyCondition(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type == "Ready" && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// Reconcile implements reconcile.Reconciler.
func (r *EdgeFunctionReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	rev := &v1alpha1.EdgeFunctionRevision{}
	err := r.Get(ctx, request.NamespacedName, rev)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get EdgeFunction: %w", err)
	}

	log := clog.FromContext(ctx, "name", rev.Name)
	log.Info("Reconciling EdgeFunctionRevision")

	if !rev.DeletionTimestamp.IsZero() {
		log.Info("Deleting EdgeFunctionRevision")
		if rev.Spec.Code.WasmSource != nil {
			log.Info("Deleting Wasm data", "ref", rev.Status.Ref)
			if err := r.wasmStore.Delete(ctx, rev.Status.Ref); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete Wasm data: %w", err)
			}
		} else if rev.Spec.Code.GoPluginSource != nil {
			log.Info("Deleting Go plugin data", "ref", rev.Status.Ref)
			if err := os.RemoveAll(filepath.Join(r.goStoreDir, rev.Status.Ref)); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete Go plugin data: %w", err)
			}
		} else if rev.Spec.Code.JsSource != nil {
			log.Info("Deleting Js data", "ref", rev.Status.Ref)
			if err := os.RemoveAll(filepath.Join(r.jsStoreDir, rev.Status.Ref)); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete Js data: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Stage the EdgeFunctionRevision that was successfully ingested (has a Ready condition)
	// even if it's not Live yet.
	if !hasReadyCondition(rev.Status.Conditions) {
		log.Info("Revision is not Ready")
		return ctrl.Result{}, nil
	}

	ref := rev.Status.Ref
	log = log.WithValues("Ref", ref)

	if rev.Spec.Code.WasmSource != nil {
		log.Info("Wasm source detected")
		if r.wasmStore.Exists(ctx, ref) {
			log.Info("Wasm module already exists for ref")
			return ctrl.Result{}, nil
		}

		wasmData, err := r.downloadFuncData(clog.IntoContext(ctx, log), "wasm", ref)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to download Wasm data: %w", err)
		}

		if err := r.wasmStore.Set(ctx, ref, manifest.WithWasmData(wasmData)); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set Wasm data: %w", err)
		}

		log.Info("Stored Wasm data")
	} else if rev.Spec.Code.GoPluginSource != nil {
		log.Info("Go plugin source detected")

		if _, err := os.Stat(filepath.Join(r.goStoreDir, ref, "func.so")); err == nil {
			log.Info("Go plugin already exists for ref")
			return ctrl.Result{}, nil
		}

		soData, err := r.downloadFuncData(clog.IntoContext(ctx, log), "go", ref)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to download Wasm data: %w", err)
		}

		if err := os.MkdirAll(filepath.Join(r.goStoreDir, ref), 0755); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create Go plugin directory: %w", err)
		}

		if err := os.WriteFile(filepath.Join(r.goStoreDir, ref, "data"), soData, 0644); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to write Go plugin data: %w", err)
		}
		// Symlinking prevents Envoy from loading the plugin while it's being written to.
		if err := os.Symlink("data", filepath.Join(r.goStoreDir, ref, "func.so")); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create Go plugin symlink: %w", err)
		}
	} else if rev.Spec.Code.JsSource != nil {
		log.Info("Js source detected")

		jsBundle, err := r.downloadFuncData(clog.IntoContext(ctx, log), "js", ref)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to download Js data: %w", err)
		}

		if err := os.MkdirAll(filepath.Join(r.jsStoreDir, ref), 0755); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create Js directory: %w", err)
		}

		if err := os.WriteFile(filepath.Join(r.jsStoreDir, ref, "data"), jsBundle, 0644); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to write Js data: %w", err)
		}
		// Use symlink to prevent Envoy from loading the plugin while it's being written to.
		esZipPath := filepath.Join(r.jsStoreDir, ref, "bin.eszip")
		if err := os.Symlink("data", esZipPath); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create Js symlink: %w", err)
		}

		r.mu.Lock()
		r.edgeFuncs[ref] = rev
		r.mu.Unlock()
	} else {
		log.Info("No source detected")
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *EdgeFunctionReconciler) reconileEdgeRuntime(ctx context.Context, ref string) error {
	log := clog.FromContext(ctx)

	s, err := r.edgeRuntime.Status(ctx, ref)
	if err != nil {
		return fmt.Errorf("failed to get Edge Runtime status: %w", err)
	}

	switch s.State {
	case edgefunc.StateRunning:
		log.Info("Edge Runtime is already running")
		return nil
	case edgefunc.StateCreated:
		log.Info("Edge Runtime is already created")
		return nil
	case edgefunc.StateStopped:
		log.Info("Edge Runtime is stopped, starting it")
	default:
		return fmt.Errorf("Edge Runtime is in an unknown state: %s", s.State)
	}

	if err := r.edgeRuntime.Start(ctx, ref, filepath.Join(r.jsStoreDir, ref, "bin.eszip")); err != nil {
		return fmt.Errorf("failed to start Edge Runtime: %w", err)
	}
	return nil
}

func targetRefPredicate(proxyName string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		rev, ok := obj.(*v1alpha1.EdgeFunctionRevision)
		if !ok {
			return false
		}

		// TODO(dilyevsky): Check if the EdgeFunction is referenced by the HTTPRoute
		// attached to one of the managed Proxies.
		return true

		// Check if the EdgeFunction is owned by the Proxy.
		for _, owner := range rev.GetOwnerReferences() {
			if owner.APIVersion == ctrlv1alpha1.GroupVersion.String() &&
				owner.Kind == "Proxy" &&
				owner.Name == proxyName {
				return true
			}
		}

		return false
	})
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *EdgeFunctionReconciler) SetupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
	proxyName string,
) error {
	if err := os.MkdirAll(filepath.Join(r.goStoreDir), 0755); err != nil {
		return fmt.Errorf("failed to create Go plugin directory: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.EdgeFunctionRevision{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				targetRefPredicate(proxyName),
			),
		).
		Complete(r)
}
