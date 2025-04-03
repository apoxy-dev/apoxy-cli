package drivers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func healthCheckAPIServer() error {
	// Poll the apiserver healthz endpoint until we get a 200
	start := time.Now()
	healthURL := "https://127.0.0.1:8443/healthz"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 500 * time.Millisecond,
	}
	for {
		resp, err := client.Get(healthURL)
		if err != nil {
			if time.Since(start) > 30*time.Second {
				return fmt.Errorf("apiserver failed to start in 30 seconds: %w", err)
			}
		}
		if resp != nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}
