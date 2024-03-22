package rest

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
)

// APIClient represents the HTTP client with API key, project ID, and base URL configuration.
type APIClient struct {
	versioned.Interface

	BaseURL    string
	BaseHost   string
	APIKey     string
	ProjectID  uuid.UUID
	HTTPClient *http.Client
}

// NewAPIClient creates a new instance of the APIClient.
func NewAPIClient(baseURL, baseHost, apiKey string, projectID uuid.UUID) (*APIClient, error) {
	tlsCfg := &tls.Config{}
	if baseHost != "" {
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.ServerName = baseHost
	}
	a3yConfig, err := newA3YRESTConfig(baseURL, baseHost, apiKey, projectID)
	if err != nil {
		return nil, fmt.Errorf("unable to create A3Y REST config: %w", err)
	}
	a3yClient, err := versioned.NewForConfig(a3yConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create A3Y client: %w", err)
	}
	return &APIClient{
		Interface: a3yClient,
		BaseURL:   baseURL,
		BaseHost:  baseHost,
		APIKey:    apiKey,
		ProjectID: projectID,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}, nil
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
