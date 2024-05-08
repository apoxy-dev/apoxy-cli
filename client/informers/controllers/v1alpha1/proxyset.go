// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	controllersv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	internalinterfaces "github.com/apoxy-dev/apoxy-cli/client/informers/internalinterfaces"
	v1alpha1 "github.com/apoxy-dev/apoxy-cli/client/listers/controllers/v1alpha1"
	versioned "github.com/apoxy-dev/apoxy-cli/client/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ProxySetInformer provides access to a shared informer and lister for
// ProxySets.
type ProxySetInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ProxySetLister
}

type proxySetInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewProxySetInformer constructs a new informer for ProxySet type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewProxySetInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredProxySetInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredProxySetInformer constructs a new informer for ProxySet type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredProxySetInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ControllersV1alpha1().ProxySets().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ControllersV1alpha1().ProxySets().Watch(context.TODO(), options)
			},
		},
		&controllersv1alpha1.ProxySet{},
		resyncPeriod,
		indexers,
	)
}

func (f *proxySetInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredProxySetInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *proxySetInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&controllersv1alpha1.ProxySet{}, f.defaultInformer)
}

func (f *proxySetInformer) Lister() v1alpha1.ProxySetLister {
	return v1alpha1.NewProxySetLister(f.Informer().GetIndexer())
}