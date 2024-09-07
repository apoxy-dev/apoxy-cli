package envoy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"

	"github.com/google/go-github/v61/github"

	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

type ReleaseDownloader interface {
	// String returns the release version.
	String() string

	// DownloadBinary downloads the release binary.
	DownloadBinary(ctx context.Context) (io.ReadCloser, error)
}

// GitHubRelease represents a release from GitHub.
type GitHubRelease struct {
	Version string
	Sha     string
	Contrib bool
}

func (r *GitHubRelease) String() string {
	if r.Sha == "" {
		return r.Version
	}
	return fmt.Sprintf("%s@sha256:%s", r.Version, r.Sha)
}

func (r *GitHubRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	release := r.String()
	if release == "" {
		c := github.NewClient(nil)
		latest, _, err := c.Repositories.GetLatestRelease(ctx, "envoyproxy", "envoy")
		if err != nil {
			return nil, fmt.Errorf("failed to get latest envoy release: %w", err)
		}
		r.Version = latest.GetTagName()
	}
	downloadURL := filepath.Join(
		githubURL,
		r.Version,
		fmt.Sprintf("envoy-%s-%s-%s", r.Version[1:], runtime.GOOS, goArchToPlatform[runtime.GOARCH]),
	)
	if r.Contrib {
		downloadURL = filepath.Join(
			githubURL,
			r.Version,
			fmt.Sprintf("envoy-contrib-%s-%s-%s", r.Version[1:], runtime.GOOS, goArchToPlatform[runtime.GOARCH]),
		)
	}

	log.Infof("downloading envoy %s from https://%s", r, downloadURL)

	resp, err := http.Get("https://" + downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download envoy: %w", err)
	}
	return resp.Body, nil
}

type URLRelease struct {
	URL string
}

func (r *URLRelease) String() string {
	return r.URL
}

func (r *URLRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	log.Infof("downloading envoy from %s", r.URL)

	resp, err := http.Get(r.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to download envoy: %w", err)
	}
	return resp.Body, nil
}
