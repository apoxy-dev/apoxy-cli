// Code generated by informer-gen. DO NOT EDIT.

package v1alpha

import (
	"context"
	time "time"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	internalinterfaces "github.com/apoxy-dev/apoxy-cli/client/informers/internalinterfaces"
	v1alpha "github.com/apoxy-dev/apoxy-cli/client/listers/core/v1alpha"
	versioned "github.com/apoxy-dev/apoxy-cli/client/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// BackendInformer provides access to a shared informer and lister for
// Backends.
type BackendInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha.BackendLister
}

type backendInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewBackendInformer constructs a new informer for Backend type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewBackendInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredBackendInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredBackendInformer constructs a new informer for Backend type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredBackendInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha().Backends().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha().Backends().Watch(context.TODO(), options)
			},
		},
		&corev1alpha.Backend{},
		resyncPeriod,
		indexers,
	)
}

func (f *backendInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredBackendInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *backendInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1alpha.Backend{}, f.defaultInformer)
}

func (f *backendInformer) Lister() v1alpha.BackendLister {
	return v1alpha.NewBackendLister(f.Informer().GetIndexer())
}
