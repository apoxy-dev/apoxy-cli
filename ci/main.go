package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"dagger.io/dagger"
	"github.com/containerd/containerd/platforms"
)

var apoxyConfigYAML = `api_key: %s
project_id: 7b08d265-24ff-4dc5-bf9f-3f387d7d8f92
api_base_url: https://api.apoxy.dev
dashboard_url: https://dashboard.apoxy.dev
`

func main() {
	if err := build(context.Background()); err != nil {
		log.Fatalf("failed to build: %v", err)
	}
}

func archOf(p dagger.Platform) string {
	return platforms.MustParse(string(p)).Architecture
}

func build(ctx context.Context) error {
	fmt.Println("Building with Dagger")

	sha := os.Getenv("GITHUB_SHA")
	if sha != "" {
		sha = sha[:10]
		if os.Getenv("APOXY_DOCKERHUB_PASSWORD") == "" {
			log.Fatal("APOXY_DOCKERHUB_PASSWORD not set")
		}
	}

	client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stderr))
	if err != nil {
		return err
	}
	defer client.Close()

	// 0. Prepare build environment.
	outPath := "build/"
	hostArch := runtime.GOARCH
	if hostArch == "arm64" {
		hostArch = "aarch64"
	} else if hostArch == "amd64" {
		hostArch = "x86_64"
	}
	builder, err := client.Container().
		From("golang:latest").
		WithDirectory("/src", client.Host().Directory("."),
			dagger.ContainerWithDirectoryOpts{
				Exclude: []string{"secrets/**"}, // exclude secrets from build context
			}).
		WithWorkdir("/src").
		WithMountedCache("/go/pkg/mod", client.CacheVolume("go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", client.CacheVolume("go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		// Install Zig toolchain.
		WithExec([]string{"apt-get", "update", "-yq"}).
		WithExec([]string{
			"apt-get", "install", "-yq", "xz-utils", "clang",
		}).
		WithExec([]string{
			"wget", fmt.Sprintf("https://ziglang.org/download/0.13.0/zig-linux-%s-0.13.0.tar.xz", hostArch),
		}).
		WithExec([]string{
			"tar", "-xf", fmt.Sprintf("zig-linux-%s-0.13.0.tar.xz", hostArch),
		}).
		WithExec([]string{
			"ln", "-s", fmt.Sprintf("/src/zig-linux-%s-0.13.0/zig", hostArch), "/bin/zig",
		}).
		WithExec([]string{
			"zig", "version",
		}).
		Sync(ctx)
	if err != nil {
		return err
	}

	// 1. Build apoxy-cli.

	cli := builder.
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "build", "-o", outPath})

	// 2. Run smoke test.
	if apiKey := os.Getenv("APOXY_PROJECT_API_KEY"); apiKey != "" {
		apoxyConfigSecret := client.SetSecret(
			"apoxy-config-yaml",
			fmt.Sprintf(apoxyConfigYAML, apiKey),
		)
		out, err := client.Container().
			From("ubuntu:22.04").
			WithExec([]string{"apt-get", "update", "-yq"}).
			WithExec([]string{
				"apt-get", "install", "-yq", "ca-certificates",
			}).
			WithFile("/usr/local/bin/apoxy", cli.File(filepath.Join(outPath, "apoxy-cli"))).
			WithExec([]string{
				"mkdir", "-p", "/root/.apoxy",
			}).
			WithMountedSecret("/root/.apoxy/config.yaml", apoxyConfigSecret).
			WithEnvVariable("CACHEBUSTER", time.Now().String()). // Force re-execution of smoke test.
			WithExec([]string{
				"apoxy", "auth", "--check",
			}).
			WithExec([]string{
				"apoxy", "proxy",
			}).
			Stdout(ctx)
		if err != nil {
			return err
		}
		fmt.Println(out)
	}

	// 3. Build and publish multi-arch Backplane/APIServer images.

	var bpContainers []*dagger.Container
	var asContainers []*dagger.Container
	for _, platform := range []dagger.Platform{"linux/amd64", "linux/arm64"} {
		goarch := archOf(platform)
		bpOut := filepath.Join("build", "backplane-"+goarch)
		dsOut := filepath.Join("build", "dial-stdio-"+goarch)

		bp := builder.
			WithEnvVariable("GOARCH", goarch).
			WithMountedCache("/go/pkg/mod", client.CacheVolume("go-mod-"+goarch)).
			WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
			WithMountedCache("/go/build-cache", client.CacheVolume("go-build-"+goarch)).
			WithEnvVariable("GOCACHE", "/go/build-cache").
			WithExec([]string{"go", "build", "-o", bpOut, "./cmd/backplane"}).
			WithExec([]string{"go", "build", "-o", dsOut, "./cmd/dial-stdio"})

		v, err := client.Container(dagger.ContainerOpts{Platform: platform}).
			From("cgr.dev/chainguard/wolfi-base:latest").
			WithFile("/bin/backplane", bp.File(bpOut)).
			WithFile("/bin/dial-stdio", bp.File(dsOut)).
			WithEntrypoint([]string{"/bin/backplane"}).
			Sync(ctx)
		if err != nil {
			return err
		}
		bpContainers = append(bpContainers, v)
	}

	// TODO(dilyevsky): Fix arm64 build.
	platform := dagger.Platform("linux/amd64")
	goarch := "amd64"
	target := "x86_64"
	asOut := filepath.Join("build", "apiserver-"+goarch)
	asrv := builder.
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig cc --target=%s-linux-musl", target)).
		WithExec([]string{"go", "build", "-o", asOut, "./cmd/apiserver"})

	v, err := client.Container(dagger.ContainerOpts{Platform: platform}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithFile("/bin/apiserver", asrv.File(asOut)).
		WithEntrypoint([]string{"/bin/apiserver"}).
		Sync(ctx)
	if err != nil {
		return err
	}
	asContainers = append(asContainers, v)

	if sha == "" {
		// Skip publishing if not in a CI environment.
		return nil
	}

	bpOpts := dagger.ContainerPublishOpts{
		PlatformVariants: bpContainers,
	}
	asOpts := dagger.ContainerPublishOpts{
		PlatformVariants: asContainers,
	}
	for _, tag := range []string{"latest", sha} {
		_, err = client.Container().
			WithRegistryAuth(
				"docker.io",
				"apoxy",
				client.SetSecret("dockerhub-apoxy", os.Getenv("APOXY_DOCKERHUB_PASSWORD")),
			).
			Publish(ctx, "docker.io/apoxy/backplane:"+tag, bpOpts)
		if err != nil {
			return err
		}

		_, err = client.Container().
			WithRegistryAuth(
				"docker.io",
				"apoxy",
				client.SetSecret("dockerhub-apoxy", os.Getenv("APOXY_DOCKERHUB_PASSWORD")),
			).
			Publish(ctx, "docker.io/apoxy/apiserver:"+tag, asOpts)
		if err != nil {
			return err
		}
	}

	return nil
}
