// Code generated by client-gen. DO NOT EDIT.

package v1alpha

import (
	"context"
	"time"

	v1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	scheme "github.com/apoxy-dev/apoxy-cli/client/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// AddressesGetter has a method to return a AddressInterface.
// A group's client should implement this interface.
type AddressesGetter interface {
	Addresses() AddressInterface
}

// AddressInterface has methods to work with Address resources.
type AddressInterface interface {
	Create(ctx context.Context, address *v1alpha.Address, opts v1.CreateOptions) (*v1alpha.Address, error)
	Update(ctx context.Context, address *v1alpha.Address, opts v1.UpdateOptions) (*v1alpha.Address, error)
	UpdateStatus(ctx context.Context, address *v1alpha.Address, opts v1.UpdateOptions) (*v1alpha.Address, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha.Address, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha.AddressList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.Address, err error)
	AddressExpansion
}

// addresses implements AddressInterface
type addresses struct {
	client rest.Interface
}

// newAddresses returns a Addresses
func newAddresses(c *CoreV1alphaClient) *addresses {
	return &addresses{
		client: c.RESTClient(),
	}
}

// Get takes name of the address, and returns the corresponding address object, and an error if there is any.
func (c *addresses) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha.Address, err error) {
	result = &v1alpha.Address{}
	err = c.client.Get().
		Resource("addresses").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Addresses that match those selectors.
func (c *addresses) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha.AddressList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha.AddressList{}
	err = c.client.Get().
		Resource("addresses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested addresses.
func (c *addresses) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("addresses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a address and creates it.  Returns the server's representation of the address, and an error, if there is any.
func (c *addresses) Create(ctx context.Context, address *v1alpha.Address, opts v1.CreateOptions) (result *v1alpha.Address, err error) {
	result = &v1alpha.Address{}
	err = c.client.Post().
		Resource("addresses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(address).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a address and updates it. Returns the server's representation of the address, and an error, if there is any.
func (c *addresses) Update(ctx context.Context, address *v1alpha.Address, opts v1.UpdateOptions) (result *v1alpha.Address, err error) {
	result = &v1alpha.Address{}
	err = c.client.Put().
		Resource("addresses").
		Name(address.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(address).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *addresses) UpdateStatus(ctx context.Context, address *v1alpha.Address, opts v1.UpdateOptions) (result *v1alpha.Address, err error) {
	result = &v1alpha.Address{}
	err = c.client.Put().
		Resource("addresses").
		Name(address.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(address).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the address and deletes it. Returns an error if one occurs.
func (c *addresses) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("addresses").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *addresses) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("addresses").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched address.
func (c *addresses) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.Address, err error) {
	result = &v1alpha.Address{}
	err = c.client.Patch(pt).
		Resource("addresses").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}