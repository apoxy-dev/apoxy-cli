// Package docker implements Docker utils.
package docker

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"k8s.io/utils/strings/slices"

	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

const (
	NetworkName = "apoxy"
)

type Option func(*options)

type options struct {
	labels map[string]string
}

func defaultOptions() *options {
	return &options{
		labels: map[string]string{},
	}
}

// WithLabel sets the container label pair to match.
// If called multiple times, the labels are ANDed.
func WithLabel(key, value string) Option {
	return func(o *options) {
		o.labels[key] = value
	}
}
func runningContainers(ctx context.Context, namePrefix string) ([]string, error) {
	out, err := exec.CommandContext(ctx,
		"docker", "ps",
		"--no-trunc",
		"--filter", "name=^"+namePrefix,
		"--format", "{{.Names}}",
	).CombinedOutput()
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, err
	}
	log.Debugf("running containers: %s", out)
	return strings.Split(string(out), "\n"), nil
}

func matchContainer(
	ctx context.Context,
	containers []string,
	cname string,
	labels map[string]string,
) (string, bool) {
	log.Debugf("matching container %q with labels %v", cname, labels)
	for _, c := range containers {
		if matchLabel(ctx, c, labels) &&
			cname == c {
			return c, true
		}
	}
	return "", false
}

func matchLabel(ctx context.Context, container string, labels map[string]string) bool {
	for key, value := range labels {
		labelValue, err := exec.CommandContext(ctx,
			"docker", "inspect",
			"--format", "{{index .Config.Labels \""+key+"\"}}",
			container,
		).CombinedOutput()
		if err != nil {
			return false
		}
		if strings.TrimSpace(string(labelValue)) != value {
			return false
		}
	}
	return true
}

func gcContainers(ctx context.Context, containers []string) error {
	if len(containers) == 0 {
		return nil
	}
	cmd := exec.CommandContext(ctx,
		"docker", "rm", "-fv",
	)
	cmd.Args = append(cmd.Args, containers...)
	return cmd.Run()
}

func containerSHA(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to parse image reference: %w", err)
	}

	img, err := remote.Get(
		ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return "", fmt.Errorf("failed to fetch image %s: %w", ref.Name(), err)
	}

	return img.Digest.String(), nil
}

// Collect finds running containers, garbage collects dangling containers if needed,
// and returns the matchine container name.
func Collect(ctx context.Context, namePrefix, imageRef string, opts ...Option) (string, bool, error) {
	dOpts := defaultOptions()
	for _, opt := range opts {
		opt(dOpts)
	}

	sha, err := containerSHA(imageRef)
	if err != nil {
		return "", false, fmt.Errorf("Failed to get image digest: %v", err)
	}
	cs, err := runningContainers(ctx, namePrefix)
	if err != nil {
		return "", false, fmt.Errorf("Failed to list running containers: %v", err)
	}
	containerName := namePrefix + strings.TrimPrefix(sha, "sha256:")[:12]
	c, found := matchContainer(ctx, cs, containerName, dOpts.labels)

	var dangling []string
	dangling = slices.Filter(dangling, cs, func(e string) bool {
		return e != c
	})
	if err := gcContainers(ctx, dangling); err != nil {
		return "", false, fmt.Errorf("Failed to remove dangling containers: %v", err)
	}

	return containerName, found, nil
}
