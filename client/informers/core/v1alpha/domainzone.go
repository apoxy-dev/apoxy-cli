/*
Copyright 2024 Apoxy, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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

// DomainZoneInformer provides access to a shared informer and lister for
// DomainZones.
type DomainZoneInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha.DomainZoneLister
}

type domainZoneInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewDomainZoneInformer constructs a new informer for DomainZone type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewDomainZoneInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredDomainZoneInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredDomainZoneInformer constructs a new informer for DomainZone type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredDomainZoneInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha().DomainZones().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha().DomainZones().Watch(context.TODO(), options)
			},
		},
		&corev1alpha.DomainZone{},
		resyncPeriod,
		indexers,
	)
}

func (f *domainZoneInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredDomainZoneInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *domainZoneInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1alpha.DomainZone{}, f.defaultInformer)
}

func (f *domainZoneInformer) Lister() v1alpha.DomainZoneLister {
	return v1alpha.NewDomainZoneLister(f.Informer().GetIndexer())
}
