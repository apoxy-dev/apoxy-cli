// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	scheme "github.com/apoxy-dev/apoxy-cli/client/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// EdgeFunctionsGetter has a method to return a EdgeFunctionInterface.
// A group's client should implement this interface.
type EdgeFunctionsGetter interface {
	EdgeFunctions() EdgeFunctionInterface
}

// EdgeFunctionInterface has methods to work with EdgeFunction resources.
type EdgeFunctionInterface interface {
	Create(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.CreateOptions) (*v1alpha1.EdgeFunction, error)
	Update(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.UpdateOptions) (*v1alpha1.EdgeFunction, error)
	UpdateStatus(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.UpdateOptions) (*v1alpha1.EdgeFunction, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.EdgeFunction, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.EdgeFunctionList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.EdgeFunction, err error)
	EdgeFunctionExpansion
}

// edgeFunctions implements EdgeFunctionInterface
type edgeFunctions struct {
	client rest.Interface
}

// newEdgeFunctions returns a EdgeFunctions
func newEdgeFunctions(c *ExtensionsV1alpha1Client) *edgeFunctions {
	return &edgeFunctions{
		client: c.RESTClient(),
	}
}

// Get takes name of the edgeFunction, and returns the corresponding edgeFunction object, and an error if there is any.
func (c *edgeFunctions) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.EdgeFunction, err error) {
	result = &v1alpha1.EdgeFunction{}
	err = c.client.Get().
		Resource("edgefunctions").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of EdgeFunctions that match those selectors.
func (c *edgeFunctions) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.EdgeFunctionList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.EdgeFunctionList{}
	err = c.client.Get().
		Resource("edgefunctions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested edgeFunctions.
func (c *edgeFunctions) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("edgefunctions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a edgeFunction and creates it.  Returns the server's representation of the edgeFunction, and an error, if there is any.
func (c *edgeFunctions) Create(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.CreateOptions) (result *v1alpha1.EdgeFunction, err error) {
	result = &v1alpha1.EdgeFunction{}
	err = c.client.Post().
		Resource("edgefunctions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(edgeFunction).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a edgeFunction and updates it. Returns the server's representation of the edgeFunction, and an error, if there is any.
func (c *edgeFunctions) Update(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.UpdateOptions) (result *v1alpha1.EdgeFunction, err error) {
	result = &v1alpha1.EdgeFunction{}
	err = c.client.Put().
		Resource("edgefunctions").
		Name(edgeFunction.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(edgeFunction).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *edgeFunctions) UpdateStatus(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.UpdateOptions) (result *v1alpha1.EdgeFunction, err error) {
	result = &v1alpha1.EdgeFunction{}
	err = c.client.Put().
		Resource("edgefunctions").
		Name(edgeFunction.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(edgeFunction).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the edgeFunction and deletes it. Returns an error if one occurs.
func (c *edgeFunctions) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("edgefunctions").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *edgeFunctions) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("edgefunctions").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched edgeFunction.
func (c *edgeFunctions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.EdgeFunction, err error) {
	result = &v1alpha1.EdgeFunction{}
	err = c.client.Patch(pt).
		Resource("edgefunctions").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
