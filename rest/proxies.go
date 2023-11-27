package rest

import (
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
func (c *ProxyClient) Get(name string) (*Proxy, error) {
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
