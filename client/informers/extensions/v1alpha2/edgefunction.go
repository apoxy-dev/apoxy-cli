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

package v1alpha2

import (
	"context"
	time "time"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha2"
	internalinterfaces "github.com/apoxy-dev/apoxy-cli/client/informers/internalinterfaces"
	v1alpha2 "github.com/apoxy-dev/apoxy-cli/client/listers/extensions/v1alpha2"
	versioned "github.com/apoxy-dev/apoxy-cli/client/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// EdgeFunctionInformer provides access to a shared informer and lister for
// EdgeFunctions.
type EdgeFunctionInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha2.EdgeFunctionLister
}

type edgeFunctionInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewEdgeFunctionInformer constructs a new informer for EdgeFunction type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewEdgeFunctionInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredEdgeFunctionInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredEdgeFunctionInformer constructs a new informer for EdgeFunction type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredEdgeFunctionInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ExtensionsV1alpha2().EdgeFunctions().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ExtensionsV1alpha2().EdgeFunctions().Watch(context.TODO(), options)
			},
		},
		&extensionsv1alpha2.EdgeFunction{},
		resyncPeriod,
		indexers,
	)
}

func (f *edgeFunctionInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredEdgeFunctionInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *edgeFunctionInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&extensionsv1alpha2.EdgeFunction{}, f.defaultInformer)
}

func (f *edgeFunctionInformer) Lister() v1alpha2.EdgeFunctionLister {
	return v1alpha2.NewEdgeFunctionLister(f.Informer().GetIndexer())
}