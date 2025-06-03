package rest

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"k8s.io/client-go/rest"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/client/versioned"
)

// APIClient represents the HTTP client with API key, project ID, and base URL configuration.
type APIClient struct {
	versioned.Interface

	BaseURL    string
	BaseHost   string
	APIKey     string
	ProjectID  uuid.UUID
	RESTConfig *rest.Config

	HTTPClient *http.Client
}

// Option defines a configuration option for the APIClient.
type Option func(*APIClient)

// WithBaseURL sets the base URL for the APIClient.
func WithBaseURL(baseURL string) Option {
	return func(c *APIClient) {
		c.BaseURL = baseURL
	}
}

// WithBaseHost sets the base host for the APIClient.
func WithBaseHost(baseHost string) Option {
	return func(c *APIClient) {
		c.BaseHost = baseHost
	}
}

// WithAPIKey sets the API key for the APIClient.
func WithAPIKey(apiKey string) Option {
	return func(c *APIClient) {
		c.APIKey = apiKey
	}
}

// WithProjectID sets the project ID for the APIClient.
func WithProjectID(projectID uuid.UUID) Option {
	return func(c *APIClient) {
		c.ProjectID = projectID
	}
}

// WithK8sConfig sets the Kubernetes configuration for the APIClient.
// If set, overriedes baseURL, baseHost, APIKey, and ProjectID.
func WithK8sConfig(cfg *rest.Config) Option {
	return func(c *APIClient) {
		c.RESTConfig = cfg
	}
}

// NewAPIClient creates a new instance of the APIClient.
func NewAPIClient(opts ...Option) (*APIClient, error) {
	client := &APIClient{}

	for _, opt := range opts {
		opt(client)
	}

	tlsCfg := &tls.Config{}
	if client.BaseHost != "" {
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.ServerName = client.BaseHost
	}

	if client.RESTConfig == nil {
		var err error
		client.RESTConfig, err = newA3YRESTConfig(client.BaseURL, client.BaseHost, client.APIKey, client.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("unable to create A3Y REST config: %w", err)
		}
	}

	a3yClient, err := versioned.NewForConfig(client.RESTConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create A3Y client: %w", err)
	}

	client.Interface = a3yClient
	client.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	return client, nil
}

// SendRequest sends an HTTP request with the configured headers.
func (c *APIClient) SendRequest(method, path string, body []byte) (*http.Response, error) {
	url := c.BaseURL + path
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("X-Apoxy-API-Key", c.APIKey)
	req.Header.Set("X-Apoxy-Project-Id", c.ProjectID.String())
	req.Header.Set("User-Agent", build.UserAgent())
	if c.BaseHost != "" {
		req.Host = c.BaseHost
	}

	// Send the request
	return c.HTTPClient.Do(req)
}
