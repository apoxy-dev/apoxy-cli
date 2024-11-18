// Package extensions implements extensions controllers.
package extensions

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	"go.temporal.io/api/serviceerror"
	tclient "go.temporal.io/sdk/client"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy-cli/pkg/apiserver/ingest"

	"github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
)

var _ reconcile.Reconciler = &EdgeFunctionReconciler{}

// EdgeFunctionReconciler reconciles a Proxy object.
type EdgeFunctionReconciler struct {
	client.Client
	tc tclient.Client
}

// NewEdgeFuncReconciler returns a new reconcile.Reconciler.
func NewEdgeFuncReconciler(
	c client.Client,
	tc tclient.Client,
) *EdgeFunctionReconciler {
	return &EdgeFunctionReconciler{
		Client: c,
		tc:     tc,
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *EdgeFunctionReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	f := &v1alpha1.EdgeFunction{}
	err := r.Get(ctx, request.NamespacedName, f)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get EdgeFunction: %w", err)
	}

	log := clog.FromContext(ctx, "name", f.Name)
	log.Info("Reconciling EdgeFunction", "phase", f.Status.Phase)

	if !f.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("EdgeFunction is being deleted")
		if err := r.cancelIngestWorkflow(ctx, f); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cancel ingest workflow: %w", err)
		}
		return ctrl.Result{}, nil
	}

	switch f.Status.Phase {
	case v1alpha1.EdgeFunctionPhasePreparing, v1alpha1.EdgeFunctionPhaseUpdating:
		if ref, started, err := r.startIngestWorkflow(clog.IntoContext(ctx, log), f); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to start ingest workflow: %w", err)
		} else if started { // Still running, or just started - requeue to check on it later.
			log.Info("Ingest workflow is running", "ref", ref)
			return ctrl.Result{}, nil
		} else if ref == "" {
			// Workflow sets the status when completed, so if it's not running,
			// and the state is still Preparing or Updating, it means the workflow failed.
			log.Info("Ingest workflow is not running, switching to Unknown phase", "ref", ref)
			f.Status.Phase = v1alpha1.EdgeFunctionPhaseUnknown
			if err := r.Status().Update(ctx, f); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update EdgeFunction: %w", err)
			}
		}
	case v1alpha1.EdgeFunctionPhaseReady:
		log.Info("EdgeFunction is ready, detecting changes")
		if ref, started, err := r.startIngestWorkflow(clog.IntoContext(ctx, log), f); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to start ingest workflow: %w", err)
		} else if started {
			log.Info("Detected changes in EdgeFunction code, switching to Updating phase")
			// Workflow with the given ID not found, means we haven't ingested this configuration yet.
			// Switch the state to Updating to trigger a new ingest.
			f.Status.Phase = v1alpha1.EdgeFunctionPhaseUpdating
			if err := r.Status().Update(ctx, f); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update EdgeFunction: %w", err)
			}
		} else if ref != "" { // Found existing ref - bump it to the top.
			log.Info("Found existing EdgeFunction revision, setting to live", "ref", ref)

			f.Status.Live = ref

			if err := r.Status().Update(ctx, f); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update EdgeFunction: %w", err)
			}
		}
	default:
		log.Info("EdgeFunction is in an unknown phase", "phase", f.Status.Phase)
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *EdgeFunctionReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.EdgeFunction{}).
		Complete(r)
}

func (r *EdgeFunctionReconciler) findExistingRef(
	ctx context.Context,
	ref string,
	obj *v1alpha1.EdgeFunction,
) bool {
	log := clog.FromContext(ctx, "ref", ref)

	for _, rev := range obj.Status.Revisions {
		if rev.Ref == ref {
			log.Info("Workflow with the given ref already exists in status")
			return true
		}
	}

	return false
}

func (r *EdgeFunctionReconciler) startIngestWorkflow(
	ctx context.Context,
	obj *v1alpha1.EdgeFunction,
) (ref string, srarted bool, err error) {
	wid, err := ingest.WorkflowID(obj)
	if err != nil {
		return "", false, fmt.Errorf("failed to get workflow ID: %w", err)
	}
	log := clog.FromContext(ctx, "workflow_id", wid)

	if exists := r.findExistingRef(clog.IntoContext(ctx, log), wid, obj); exists {
		return wid, false, nil
	}

	log.Info("Starting ingest workflow")

	wOpts := tclient.StartWorkflowOptions{
		ID:                       wid,
		TaskQueue:                ingest.EdgeFunctionIngestQueue,
		WorkflowExecutionTimeout: 10 * time.Minute,
	}
	in := &ingest.EdgeFunctionIngestParams{
		Obj: obj.DeepCopy(),
	}
	if _, err = r.tc.ExecuteWorkflow(ctx, wOpts, ingest.EdgeFunctionIngestWorkflow, in); err != nil {
		return "", false, fmt.Errorf("failed to start ingest workflow: %w", err)
	}
	return wid, true, nil
}

func (r *EdgeFunctionReconciler) cancelIngestWorkflow(ctx context.Context, obj *v1alpha1.EdgeFunction) error {
	wid, err := ingest.WorkflowID(obj)
	if err != nil {
		return fmt.Errorf("failed to get workflow ID: %w", err)
	}
	log := clog.FromContext(ctx, "workflow_id", wid)

	log.Info("Cancelling ingest workflow")

	if err := r.tc.CancelWorkflow(ctx, wid, ""); err != nil {
		var serviceErr *serviceerror.NotFound
		if !goerrors.As(err, &serviceErr) {
			return fmt.Errorf("failed to describe workflow execution: %w", err)
		}
		log.Info("Workflow is not found, nothing to cancel")
	}
	return nil
}
