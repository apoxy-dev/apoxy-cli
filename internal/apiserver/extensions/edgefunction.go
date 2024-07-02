// Package extensions implements extensions controllers.
package extensions

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
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
	case v1alpha1.EdgeFunctionPhasePreparing:
		if err := r.startIngestWorkflow(clog.IntoContext(ctx, log), f); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to start ingest workflow: %w", err)
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

func (r *EdgeFunctionReconciler) startIngestWorkflow(ctx context.Context, obj *v1alpha1.EdgeFunction) error {
	wid := ingest.WorkflowID(obj)
	log := clog.FromContext(ctx, "workflow_id", wid)

	res, err := r.tc.DescribeWorkflowExecution(ctx, wid, "" /* RunID */)
	if err != nil {
		var serviceErr *serviceerror.NotFound
		if !goerrors.As(err, &serviceErr) {
			return fmt.Errorf("failed to describe workflow execution: %w", err)
		}
	} else if res.WorkflowExecutionInfo.GetStatus() == enums.WORKFLOW_EXECUTION_STATUS_RUNNING {
		log.Info("Workflow is already running, returning")
		return nil
	} else {
		log.Info("Workflow is not running, starting new workflow", "status", res.WorkflowExecutionInfo.GetStatus())
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
	wid := ingest.WorkflowID(obj)
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
