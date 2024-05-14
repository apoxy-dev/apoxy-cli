// Package drivers implements Backplane drivers (e.g Docker, Kubernetes, etc.)
package drivers

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"k8s.io/utils/strings/slices"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

const (
	containerNamePrefix = "apoxy-backplane-"
	imageRepo           = "docker.io/apoxy/backplane"
)

type Driver interface {
	// Deploy deploys the proxy.
	Start(ctx context.Context, orgID uuid.UUID, proxyName string) error
}

func GetDriver(driver string) Driver {
	return &dockerDriver{}
}

type dockerDriver struct{}

func runningContainers(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx,
		"docker", "ps",
		"--no-trunc",
		"--filter", "name=^"+containerNamePrefix,
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
	proxyName string,
) (string, bool) {
	log.Debugf("matching container %q with labels org.apoxy.machine=%s", cname, proxyName)
	for _, c := range containers {
		if matchLabel(ctx, c, "org.apoxy.machine", proxyName) &&
			cname == c {
			return c, true
		}
	}
	return "", false
}

func matchLabel(ctx context.Context, container, key, value string) bool {
	out, err := exec.CommandContext(ctx,
		"docker", "inspect",
		"--format", "{{index .Config.Labels \""+key+"\"}}",
		container,
	).CombinedOutput()
	if err != nil {
		return false
	}
	log.Debugf("container %q label %q: %s", container, key, out)
	return strings.TrimSpace(string(out)) == value
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

func imageRef() string {
	imgTag := build.BuildVersion
	if build.IsDev() {
		imgTag = "5fc5dac51b"
	}
	return imageRepo + ":" + imgTag
}

func containerSHA(ctx context.Context, imageRef string) (string, error) {
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

func (d *dockerDriver) Start(ctx context.Context, orgID uuid.UUID, proxyName string) error {
	imageRef := imageRef()
	sha, err := containerSHA(ctx, imageRef)
	if err != nil {
		return err
	}
	cs, err := runningContainers(ctx)
	if err != nil {
		return err
	}
	containerName := containerNamePrefix + strings.TrimPrefix(sha, "sha256:")[:12]
	c, found := matchContainer(ctx, cs, containerName, proxyName)
	defer func() {
		var dangling []string
		dangling = slices.Filter(dangling, cs, func(e string) bool {
			return e != c
		})
		if err := gcContainers(ctx, dangling); err != nil {
			log.Errorf("Failed to remove dangling containers: %v", err)
		}
	}()

	if found {
		log.Debugf("Container %s already running", c)
		return nil
	}

	// Pull the image.
	if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageRef, err)
	}

	log.Errorf("Starting container %s", containerName)
	cmd := exec.CommandContext(ctx,
		"docker",
		"run",
		"--name", containerName,
		"--label", "org.apoxy.machine="+proxyName,
		"-d",
		"--restart", "always",
		"--privileged",
	)

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--project_id=" + orgID.String(),
		"--proxy_name=" + proxyName,
		"--apiserver_host=host.docker.internal",
	}...)

	log.Errorf("Running command: %v", cmd.String())

	return cmd.Run()
}
