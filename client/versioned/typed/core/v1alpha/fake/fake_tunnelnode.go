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
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeTunnelNodes implements TunnelNodeInterface
type FakeTunnelNodes struct {
	Fake *FakeCoreV1alpha
}

var tunnelnodesResource = v1alpha.SchemeGroupVersion.WithResource("tunnelnodes")

var tunnelnodesKind = v1alpha.SchemeGroupVersion.WithKind("TunnelNode")

// Get takes name of the tunnelNode, and returns the corresponding tunnelNode object, and an error if there is any.
func (c *FakeTunnelNodes) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha.TunnelNode, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(tunnelnodesResource, name), &v1alpha.TunnelNode{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.TunnelNode), err
}

// List takes label and field selectors, and returns the list of TunnelNodes that match those selectors.
func (c *FakeTunnelNodes) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha.TunnelNodeList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(tunnelnodesResource, tunnelnodesKind, opts), &v1alpha.TunnelNodeList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha.TunnelNodeList{ListMeta: obj.(*v1alpha.TunnelNodeList).ListMeta}
	for _, item := range obj.(*v1alpha.TunnelNodeList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested tunnelNodes.
func (c *FakeTunnelNodes) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(tunnelnodesResource, opts))
}

// Create takes the representation of a tunnelNode and creates it.  Returns the server's representation of the tunnelNode, and an error, if there is any.
func (c *FakeTunnelNodes) Create(ctx context.Context, tunnelNode *v1alpha.TunnelNode, opts v1.CreateOptions) (result *v1alpha.TunnelNode, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(tunnelnodesResource, tunnelNode), &v1alpha.TunnelNode{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.TunnelNode), err
}

// Update takes the representation of a tunnelNode and updates it. Returns the server's representation of the tunnelNode, and an error, if there is any.
func (c *FakeTunnelNodes) Update(ctx context.Context, tunnelNode *v1alpha.TunnelNode, opts v1.UpdateOptions) (result *v1alpha.TunnelNode, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(tunnelnodesResource, tunnelNode), &v1alpha.TunnelNode{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.TunnelNode), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeTunnelNodes) UpdateStatus(ctx context.Context, tunnelNode *v1alpha.TunnelNode, opts v1.UpdateOptions) (*v1alpha.TunnelNode, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(tunnelnodesResource, "status", tunnelNode), &v1alpha.TunnelNode{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.TunnelNode), err
}

// Delete takes name of the tunnelNode and deletes it. Returns an error if one occurs.
func (c *FakeTunnelNodes) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(tunnelnodesResource, name, opts), &v1alpha.TunnelNode{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeTunnelNodes) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(tunnelnodesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha.TunnelNodeList{})
	return err
}

// Patch applies the patch and returns the patched tunnelNode.
func (c *FakeTunnelNodes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.TunnelNode, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(tunnelnodesResource, name, pt, data, subresources...), &v1alpha.TunnelNode{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.TunnelNode), err
}
