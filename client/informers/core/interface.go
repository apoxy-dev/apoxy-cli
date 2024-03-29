// Code generated by informer-gen. DO NOT EDIT.

package core

import (
	v1alpha "github.com/apoxy-dev/apoxy-cli/client/informers/core/v1alpha"
	internalinterfaces "github.com/apoxy-dev/apoxy-cli/client/informers/internalinterfaces"
)

// Interface provides access to each of this group's versions.
type Interface interface {
	// V1alpha provides access to shared informers for resources in V1alpha.
	V1alpha() v1alpha.Interface
}

type group struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &group{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// V1alpha returns a new v1alpha.Interface.
func (g *group) V1alpha() v1alpha.Interface {
	return v1alpha.New(g.factory, g.namespace, g.tweakListOptions)
}
