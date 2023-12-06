package rest

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

type DomainClient struct {
	client *K8SClient
}

// Domain returns a client for Domain objects.
func (c *APIClient) Domain() *DomainClient {
	return &DomainClient{
		client: c.K8SClient,
	}
}

// Get returns a Domain object.
func (c *DomainClient) Get(name string) (*v1alpha.Domain, error) {
	var domain v1alpha.Domain
	result, err := c.client.client.
		Resource(domain.GetGroupVersionResource()).
		Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &domain)
	if err != nil {
		return nil, err
	}
	return &domain, err
}

// List returns all of Domain object.
func (c *DomainClient) List() (*v1alpha.DomainList, error) {
	var domain v1alpha.Domain
	result, err := c.client.client.
		Resource(domain.GetGroupVersionResource()).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var domainList v1alpha.DomainList
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &domainList)
	if err != nil {
		return nil, err
	}
	return &domainList, err
}

// Create creates a Domain object.
func (c *DomainClient) Create(domain *v1alpha.Domain) (*v1alpha.Domain, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(domain)
	if err != nil {
		return nil, err
	}
	result, err := c.client.client.
		Resource(domain.GetGroupVersionResource()).
		Create(context.TODO(), &unstructured.Unstructured{
			Object: unstructuredObj,
		}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	var rdomain v1alpha.Domain
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(result.UnstructuredContent(), &rdomain)
	if err != nil {
		return nil, err
	}
	return &rdomain, err
}

// Delete deletes a Domain object.
func (c *DomainClient) Delete(name string) error {
	var domain v1alpha.Domain
	return c.client.client.
		Resource(domain.GetGroupVersionResource()).
		Delete(context.TODO(), name, metav1.DeleteOptions{})
}
