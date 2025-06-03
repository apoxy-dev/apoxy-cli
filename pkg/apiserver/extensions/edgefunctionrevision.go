package extensions

import (
	"context"
	"sort"
	"time"

	tclient "go.temporal.io/sdk/client"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/ingest"
)

const (
	controllerKey = ".metadata.controller"
)

var _ reconcile.Reconciler = &EdgeFunctionRevisionGCReconciler{}

// EdgeFunctionRevisionGCReconciler garbage collects EdgeFunctionRevisions.
type EdgeFunctionRevisionGCReconciler struct {
	client.Client
	scheme     *runtime.Scheme
	tc         tclient.Client
	gcInterval time.Duration
}

// NewEdgeFunctionRevisionGCReconciler returns a new EdgeFunctionRevisionGCReconciler.
func NewEdgeFunctionRevisionGCReconciler(
	c client.Client,
	s *runtime.Scheme,
	tc tclient.Client,
	gcInterval time.Duration,
) *EdgeFunctionRevisionGCReconciler {
	return &EdgeFunctionRevisionGCReconciler{
		Client:     c,
		scheme:     s,
		tc:         tc,
		gcInterval: gcInterval,
	}
}

// Reconcile implements reconcile.Reconciler
func (r *EdgeFunctionRevisionGCReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := clog.FromContext(ctx).WithValues("EdgeFunction", req.NamespacedName)
	log.Info("Garbage collecting EdgeFunctionRevisions")

	var ef extensionsv1alpha2.EdgeFunction
	if err := r.Get(ctx, req.NamespacedName, &ef); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	var revs extensionsv1alpha2.EdgeFunctionRevisionList
	if err := r.List(ctx, &revs, client.MatchingFields{controllerKey: ef.Name}); err != nil {
		return reconcile.Result{}, err
	}

	sort.Slice(revs.Items, func(i, j int) bool {
		return revs.Items[i].CreationTimestamp.Before(&revs.Items[j].CreationTimestamp)
	})

	// Delete old revisions if we're over the limit as defined in the owner's spec.
	if ef.Spec.RevisionHistoryLimit != nil {
		limit := int(*ef.Spec.RevisionHistoryLimit)
		if len(revs.Items) > limit {
			log.Info("EdgeFunctionRevision limit reached, deleting old revisions", "limit", limit, "count", len(revs.Items))
			for i := 0; i < len(revs.Items)-limit; i++ {
				revision := &revs.Items[i]
				if revision.Name == ef.Status.LiveRevision {
					log.Info("Skipping deletion of live revision", "revision", revision.Name)
					continue
				}
				if err := r.Delete(ctx, revision); err != nil {
					log.Error(err, "Failed to delete old revision", "revision", revision.Name)
					continue
				}
				// Execute cleanup workflow.
				wOpts := tclient.StartWorkflowOptions{
					ID:                       revision.Name + "-cleanup",
					TaskQueue:                ingest.EdgeFunctionIngestQueue,
					WorkflowExecutionTimeout: 10 * time.Minute,
				}
				in := &ingest.EdgeFunctionIngestParams{
					Obj: revision.DeepCopy(),
				}
				if _, err := r.tc.ExecuteWorkflow(ctx, wOpts, ingest.EdgeFunctionCleanupWorkflow, in); err != nil {
					log.Error(err, "Failed to start cleanup workflow", "revision", revision.Name)
				}
				log.Info("Deleted old revision", "revision", revision.Name)
			}
		}
	}

	return reconcile.Result{RequeueAfter: r.gcInterval}, nil
}

// SetupWithManager sets up the reconciler with a manager
func (r *EdgeFunctionRevisionGCReconciler) SetupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
) error {
	// Set up a field indexer for EdgeFunctionRevision's metadata.controller field.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &extensionsv1alpha2.EdgeFunctionRevision{}, controllerKey, func(rawObj client.Object) []string {
		efr := rawObj.(*extensionsv1alpha2.EdgeFunctionRevision)
		owner := metav1.GetControllerOf(efr)
		if owner == nil {
			return nil
		}
		return []string{owner.Name}
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("edgefunctionrevision-gc").
		For(&extensionsv1alpha2.EdgeFunction{}).
		Complete(r)
}
