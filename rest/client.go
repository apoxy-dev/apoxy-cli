package rest

import (
	"bytes"
	"crypto/tls"
	"net/http"

	"github.com/apoxy-dev/apoxy-cli/build"
)

// APIClient represents the HTTP client with API key, project ID, and base URL configuration.
type APIClient struct {
	BaseURL    string
	BaseHost   string
	APIKey     string
	ProjectID  string
	HTTPClient *http.Client
}

// NewAPIClient creates a new instance of the APIClient.
func NewAPIClient(baseURL, baseHost, apiKey, projectID string) *APIClient {
	tlsCfg := &tls.Config{}
	if baseHost != "" {
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.ServerName = baseHost
	}
	return &APIClient{
		BaseURL:   baseURL,
		BaseHost:  baseHost,
		APIKey:    apiKey,
		ProjectID: projectID,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
}

// sendRequest sends an HTTP request with the configured headers.
func (c *APIClient) SendRequest(method, path string, body []byte) (*http.Response, error) {
	url := c.BaseURL + path
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("X-Apoxy-API-Key", c.APIKey)
	req.Header.Set("X-Apoxy-Project-Id", c.ProjectID)
	req.Header.Set("User-Agent", build.UserAgent())
	if c.BaseHost != "" {
		req.Host = c.BaseHost
	}

	// Send the request
	return c.HTTPClient.Do(req)
}
