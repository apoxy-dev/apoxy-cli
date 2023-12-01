package rest

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/apoxy-dev/apoxy-cli/build"
)

type K8SClient struct {
	client *dynamic.DynamicClient
}

func addSubdomain(baseURL, subdomain string) (*url.URL, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(parsedURL.Hostname(), ".")
	parts = append([]string{subdomain}, parts...)
	parsedURL.Host = strings.Join(parts, ".")
	return parsedURL, nil
}

func NewK8SClient(baseURL, baseHost, apiKey, projectID string) (*K8SClient, error) {
	url, err := addSubdomain(baseURL, projectID)
	if err != nil {
		return nil, err
	}
	config := &rest.Config{
		Host:      fmt.Sprintf("https://%s", url.Host),
		UserAgent: build.UserAgent(),
	}
	if baseHost != "" {
		config.Host = baseURL
		config.TLSClientConfig = rest.TLSClientConfig{
			Insecure:   true,
			ServerName: fmt.Sprintf("%s.%s", projectID, baseHost),
		}
	}
	config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		ht := &headerTransport{
			roundTripper: rt,
			apiKey:       apiKey,
			projectID:    projectID,
		}
		if baseHost != "" {
			ht.host = fmt.Sprintf("%s.%s", projectID, baseHost)
		}
		return ht
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &K8SClient{
		client: client,
	}, nil
}

type headerTransport struct {
	roundTripper http.RoundTripper
	apiKey       string
	projectID    string
	host         string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-Apoxy-API-Key", t.apiKey)
	req.Header.Set("X-Apoxy-Project-Id", t.projectID)
	req.Header.Set("User-Agent", build.UserAgent())
	if t.host != "" {
		req.Host = t.host
	}
	return t.roundTripper.RoundTrip(req)
}
