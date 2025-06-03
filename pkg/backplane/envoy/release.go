package envoy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-github/v61/github"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

type ReleaseDownloader interface {
	// String returns the release version.
	String() string

	// DownloadBinary downloads the release binary.
	DownloadBinary(ctx context.Context) (io.ReadCloser, error)
}

type LatestCachedRelease struct {
	Path    string
	version string
	gh      *GitHubRelease
}

// findLatestVersion takes a list of version strings and returns the latest one.
// It handles both semver (with or without 'v' prefix) and non-semver versions.
func findLatestVersion(versions []string) string {
	if len(versions) == 0 {
		return ""
	}

	// Sort versions
	sort.Slice(versions, func(i, j int) bool {
		// Handle 'v' prefix for semver versions
		vi := versions[i]
		vj := versions[j]

		// Strip 'v' prefix if present for comparison
		if strings.HasPrefix(vi, "v") {
			vi = vi[1:]
		}
		if strings.HasPrefix(vj, "v") {
			vj = vj[1:]
		}

		// Try to parse as semver (major.minor.patch)
		viParts := strings.Split(vi, ".")
		vjParts := strings.Split(vj, ".")

		// Compare each part numerically if possible
		minLen := len(viParts)
		if len(vjParts) < minLen {
			minLen = len(vjParts)
		}

		for k := 0; k < minLen; k++ {
			// Extract the numeric part (handle cases like "1.2.3-alpha")
			viPartBase := viParts[k]
			vjPartBase := vjParts[k]

			// Split at first non-numeric character
			viNumStr := viPartBase
			vjNumStr := vjPartBase

			for idx, c := range viNumStr {
				if c < '0' || c > '9' {
					viNumStr = viNumStr[:idx]
					break
				}
			}

			for idx, c := range vjNumStr {
				if c < '0' || c > '9' {
					vjNumStr = vjNumStr[:idx]
					break
				}
			}

			// Parse as integers
			viNum, viErr := strconv.Atoi(viNumStr)
			vjNum, vjErr := strconv.Atoi(vjNumStr)

			// If both parts are numeric, compare them numerically
			if viErr == nil && vjErr == nil {
				if viNum != vjNum {
					return viNum < vjNum
				}
				// If numeric parts are equal, compare the full parts lexicographically
				if viPartBase != vjPartBase {
					return viPartBase < vjPartBase
				}
			} else {
				// If parts aren't numeric, compare lexicographically
				if viParts[k] != vjParts[k] {
					return viParts[k] < vjParts[k]
				}
			}
		}
		if len(viParts) != len(vjParts) {
			return len(viParts) < len(vjParts)
		}

		return versions[i] < versions[j]
	})

	return versions[len(versions)-1]
}

func (r *LatestCachedRelease) findRelease() {
	// List all directories in r.Path
	entries, err := os.ReadDir(r.Path)
	if err != nil || len(entries) == 0 {
		// If no directories exist or there's an error, use GitHubRelease
		r.gh = &GitHubRelease{}
		return
	}

	// Collect directory names as versions
	versions := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}

	// If no versions found, use GitHubRelease
	if len(versions) == 0 {
		r.gh = &GitHubRelease{}
		return
	}

	// Find the latest version
	r.version = findLatestVersion(versions)
}

func (r *LatestCachedRelease) String() string {
	if r.version == "" {
		r.findRelease()
	}
	return r.version
}

func (r *LatestCachedRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	// Make sure we've found a release
	if r.version == "" {
		r.findRelease()
	}

	// If r.version is set, throw an error
	if r.version != "" {
		return nil, fmt.Errorf("downloading from cached release not implemented: %s", r.version)
	}

	// If r.gh is in use, pass the call through
	if r.gh != nil {
		return r.gh.DownloadBinary(ctx)
	}

	return nil, fmt.Errorf("no release available")
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
	return filepath.Base(r.URL)
}

func (r *URLRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	log.Infof("downloading envoy from %s", r.URL)

	resp, err := http.Get(r.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to download envoy: %w", err)
	}
	return resp.Body, nil
}
