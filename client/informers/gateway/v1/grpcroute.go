// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	gatewayv1 "github.com/apoxy-dev/apoxy-cli/api/gateway/v1"
	internalinterfaces "github.com/apoxy-dev/apoxy-cli/client/informers/internalinterfaces"
	v1 "github.com/apoxy-dev/apoxy-cli/client/listers/gateway/v1"
	versioned "github.com/apoxy-dev/apoxy-cli/client/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// GRPCRouteInformer provides access to a shared informer and lister for
// GRPCRoutes.
type GRPCRouteInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.GRPCRouteLister
}

type gRPCRouteInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewGRPCRouteInformer constructs a new informer for GRPCRoute type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewGRPCRouteInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredGRPCRouteInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredGRPCRouteInformer constructs a new informer for GRPCRoute type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredGRPCRouteInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.GatewayV1().GRPCRoutes().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.GatewayV1().GRPCRoutes().Watch(context.TODO(), options)
			},
		},
		&gatewayv1.GRPCRoute{},
		resyncPeriod,
		indexers,
	)
}

func (f *gRPCRouteInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredGRPCRouteInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *gRPCRouteInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&gatewayv1.GRPCRoute{}, f.defaultInformer)
}

func (f *gRPCRouteInformer) Lister() v1.GRPCRouteLister {
	return v1.NewGRPCRouteLister(f.Informer().GetIndexer())
}