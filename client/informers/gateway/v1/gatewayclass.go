/*
Copyright 2025 Apoxy, Inc.

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

// GatewayClassInformer provides access to a shared informer and lister for
// GatewayClasses.
type GatewayClassInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.GatewayClassLister
}

type gatewayClassInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewGatewayClassInformer constructs a new informer for GatewayClass type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewGatewayClassInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredGatewayClassInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredGatewayClassInformer constructs a new informer for GatewayClass type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredGatewayClassInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.GatewayV1().GatewayClasses().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.GatewayV1().GatewayClasses().Watch(context.TODO(), options)
			},
		},
		&gatewayv1.GatewayClass{},
		resyncPeriod,
		indexers,
	)
}

func (f *gatewayClassInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredGatewayClassInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *gatewayClassInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&gatewayv1.GatewayClass{}, f.defaultInformer)
}

func (f *gatewayClassInformer) Lister() v1.GatewayClassLister {
	return v1.NewGatewayClassLister(f.Informer().GetIndexer())
}
