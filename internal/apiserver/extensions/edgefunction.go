// Package extensions implements extensions controllers.
package extensions

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/api/workflow/v1"
	tclient "go.temporal.io/sdk/client"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/ingest"

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
		if err := r.startIngestWorkflow(clog.IntoContext(ctx, log), f); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to start ingest workflow: %w", err)
		}
	case v1alpha1.EdgeFunctionPhaseReady:
		log.Info("EdgeFunction is ready, detecting changes")
		wid, err := ingest.WorkflowID(f)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to get workflow ID: %w", err)
		}
		_, found, err := r.findIngestWorkflow(clog.IntoContext(ctx, log), wid)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to find ingest workflow: %w", err)
		} else if found {
			// Push existing ref to the top of the list.
			var revs []v1alpha1.EdgeFunctionRevision
			for i, r := range f.Status.Revisions {
				if r.Ref == wid {
					revs = append([]v1alpha1.EdgeFunctionRevision{r},
						append(f.Status.Revisions[0:i], f.Status.Revisions[i+1:]...)...)
				}
			}
			f.Status.Revisions = revs
			if err := r.Status().Update(ctx, f); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update EdgeFunction: %w", err)
			}
		} else {
			log.Info("Detected changes in EdgeFunction code, switching to Updating phase")
			// Workflow with the given ID not found, means we haven't ingested this configuration yet.
			// Switch the state to Updating to trigger a new ingest.
			f.Status.Phase = v1alpha1.EdgeFunctionPhaseUpdating
			if err := r.Status().Update(ctx, f); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update EdgeFunction: %w", err)
			}
		}
		// Workflow with the same ID found, means we have ingested this configuration - do nothing.
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

func (r *EdgeFunctionReconciler) findIngestWorkflow(ctx context.Context, wid string) (*workflow.WorkflowExecutionInfo, bool, error) {
	log := clog.FromContext(ctx, "workflow_id", wid)
	log.Info("Finding workflow")
	res, err := r.tc.DescribeWorkflowExecution(ctx, wid, "" /* RunID */)
	if err != nil {
		var serviceErr *serviceerror.NotFound
		if !goerrors.As(err, &serviceErr) {
			return nil, false, fmt.Errorf("failed to describe workflow execution: %w", err)
		}
		return nil, false, nil // Workflow not found
	}
	log.Info("Found workflow", "status", res.WorkflowExecutionInfo.GetStatus())
	return res.WorkflowExecutionInfo, true, nil
}

func (r *EdgeFunctionReconciler) startIngestWorkflow(ctx context.Context, obj *v1alpha1.EdgeFunction) error {
	wid, err := ingest.WorkflowID(obj)
	if err != nil {
		return fmt.Errorf("failed to get workflow ID: %w", err)
	}
	log := clog.FromContext(ctx, "workflow_id", wid)

	execInfo, found, err := r.findIngestWorkflow(ctx, wid)
	if err != nil {
		return err
	} else if found {
		if execInfo.GetStatus() == enums.WORKFLOW_EXECUTION_STATUS_RUNNING {
			log.Info("Workflow is already running, returning")
			return nil
		}
		log.Info("Workflow is not running, starting new workflow", "status", execInfo.GetStatus())
	} else {
		log.Info("Workflow not found, starting new workflow")
	}

	log.Info("Starting ingest workflow")

	wOpts := tclient.StartWorkflowOptions{
		ID:                       wid,
		TaskQueue:                ingest.EdgeFunctionIngestQueue,
		WorkflowExecutionTimeout: 10 * time.Minute,
	}
	in := &ingest.EdgeFunctionIngestParams{
		Obj: obj,
	}
	_, err = r.tc.ExecuteWorkflow(ctx, wOpts, ingest.EdgeFunctionIngestWorkflow, in)
	return err
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
