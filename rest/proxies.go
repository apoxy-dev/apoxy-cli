package rest

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

type ProxyClient struct {
	client *K8SClient
}

// Proxy returns a client for Proxy objects.
func (c *APIClient) Proxy() *ProxyClient {
	return &ProxyClient{
		client: c.K8SClient,
	}
}

// Get returns a Proxy object.
func (c *ProxyClient) Get(name string) (*v1alpha.Proxy, error) {
	var proxy v1alpha.Proxy
	result, err := c.client.client.
		Resource(proxy.GetGroupVersionResource()).
		Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &proxy)
	if err != nil {
		return nil, err
	}
	return &proxy, err
}

// List returns all of Proxy objects.
func (c *ProxyClient) List() (*v1alpha.ProxyList, error) {
	var proxy v1alpha.Proxy
	result, err := c.client.client.
		Resource(proxy.GetGroupVersionResource()).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var proxyList v1alpha.ProxyList
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &proxyList)
	if err != nil {
		return nil, err
	}
	return &proxyList, err
}

// ListWithOptions returns all of Proxy objects.
func (c *ProxyClient) ListWithOptions(opts metav1.ListOptions) (*v1alpha.ProxyList, error) {
	var proxy v1alpha.Proxy
	result, err := c.client.client.
		Resource(proxy.GetGroupVersionResource()).
		List(context.TODO(), opts)
	if err != nil {
		return nil, err
	}
	var proxyList v1alpha.ProxyList
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &proxyList)
	if err != nil {
		return nil, err
	}
	return &proxyList, err
}

// Create creates a Proxy object.
func (c *ProxyClient) Create(proxy *v1alpha.Proxy) (*v1alpha.Proxy, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(proxy)
	if err != nil {
		return nil, err
	}
	result, err := c.client.client.
		Resource(proxy.GetGroupVersionResource()).
		Create(context.TODO(), &unstructured.Unstructured{
			Object: unstructuredObj,
		}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	var rproxy v1alpha.Proxy
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &rproxy)
	if err != nil {
		return nil, err
	}
	return &rproxy, err
}

// Delete deletes a Proxy object.
func (c *ProxyClient) Delete(name string) error {
	var proxy v1alpha.Proxy
	return c.client.client.
		Resource(proxy.GetGroupVersionResource()).
		Delete(context.TODO(), name, metav1.DeleteOptions{})
}
