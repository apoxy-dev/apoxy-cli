// Package policy implements API Server policy controllers.
package policy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	ratelimitv3 "github.com/envoyproxy/go-control-plane/ratelimit/config/ratelimit/v3"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
)

const (
	xdsPort = 18000
)

var _ reconcile.Reconciler = &RateLimitReconciler{}

// RateLimitReconciler reconciles a Proxy object.
type RateLimitReconciler struct {
	client.Client
	orgID uuid.UUID

	cache       cache.SnapshotCache
	xdsServer   server.Server
	configCache map[string]*ratelimitv3.RateLimitConfig
}

// NewRateLimitReconciler returns a new reconcile.Reconciler for RateLimit objects.
// xDS server is configured based on the RateLimit objects and snapshots are delivered
// to connecting RateLimit services.
func NewRateLimitReconciler(
	ctx context.Context,
	c client.Client,
	orgID uuid.UUID,
) *RateLimitReconciler {
	sCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil) // TODO(dsky): Install logger.
	return &RateLimitReconciler{
		Client: c,
		orgID:  orgID,

		cache:       sCache,
		xdsServer:   server.NewServer(ctx, sCache, nil),
		configCache: make(map[string]*ratelimitv3.RateLimitConfig),
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *RateLimitReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	rl := &policyv1alpha1.RateLimit{}
	err := r.Get(ctx, request.NamespacedName, rl)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get RateLimit: %w", err)
	}

	log := log.FromContext(ctx, "name", rl.Name)
	log.Info("Reconciling RateLimit")

	if !rl.ObjectMeta.DeletionTimestamp.IsZero() { // The object is being deleted
		log.Info("RateLimit is being deleted")

		return ctrl.Result{}, nil // Deleted.
	}

	if err := r.syncSnapshot(rl); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to sync xDS snapshot: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the reconciler with the mgr.
func (r *RateLimitReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.RateLimit{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// ServeXDS starts the xDS server.
func (r *RateLimitReconciler) ServeXDS() error {
	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(1000),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    10 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	ls, err := net.Listen("tcp", fmt.Sprintf(":%d", xdsPort))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, r.xdsServer)

	log.Log.Info("Starting xDS server", "port", xdsPort)

	return grpcServer.Serve(ls)
}

// objToProto converts a RateLimitConfig to a RateLimitConfig proto.
func objToProto(rl *policyv1alpha1.RateLimit) (*ratelimitv3.RateLimitConfig, error) {
	pb := &ratelimitv3.RateLimitConfig{
		Name:        rl.Name,
		Domain:      rl.Name,
		Descriptors: make([]*ratelimitv3.RateLimitDescriptor, len(rl.Spec.Descriptors)),
	}
	for i, desc := range rl.Spec.Descriptors {
		descpb := &ratelimitv3.RateLimitDescriptor{
			Key:        desc.Key,
			Value:      desc.Value,
			ShadowMode: desc.ShadowMode,
		}
		if desc.RateLimit != nil {
			u, ok := ratelimitv3.RateLimitUnit_value[strings.ToUpper(string(desc.RateLimit.Unit))]
			if !ok {
				return nil, fmt.Errorf("invalid rate limit unit: %s", desc.RateLimit.Unit)
			}

			descpb.RateLimit = &ratelimitv3.RateLimitPolicy{
				Unit:            ratelimitv3.RateLimitUnit(u),
				RequestsPerUnit: desc.RateLimit.RequestsPerUnit,
				Unlimited:       desc.RateLimit.Unlimited,
			}
		}

		pb.Descriptors[i] = descpb
	}
	return pb, nil
}

func (r *RateLimitReconciler) syncSnapshot(rl *policyv1alpha1.RateLimit) error {
	pb, err := objToProto(rl)
	if err != nil {
		return fmt.Errorf("failed to convert RateLimit to proto: %w", err)
	}
	r.configCache[rl.Name] = pb

	rs := make([]types.Resource, 0, len(r.configCache))
	for _, v := range r.configCache {
		rs = append(rs, v)
	}
	s, err := cache.NewSnapshot(
		"1",
		map[resource.Type][]types.Resource{
			resource.RateLimitConfigType: rs,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}
	if err := s.Consistent(); err != nil {
		return fmt.Errorf("inconsistent snapshot: %w", err)
	}

	return nil
}
