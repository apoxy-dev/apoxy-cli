package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"dagger.io/dagger"
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

func build(ctx context.Context) error {
	fmt.Println("Building with Dagger")

	apoxyAPIKey := os.Getenv("APOXY_PROJECT_API_KEY")
	if apoxyAPIKey == "" {
		log.Fatal("APOXY_PROJECT_API_KEY not set")
	}
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" {
		log.Fatal("GITHUB_SHA not set")
	}
	sha = sha[:10]

	client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stderr))
	if err != nil {
		return err
	}
	defer client.Close()

	// 1. Build binaries.
	outPath := "build/"
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
		WithExec([]string{"go", "build", "-o", outPath}).
		WithExec([]string{"go", "build", "-o", outPath, "./cmd/backplane"}).
		Sync(ctx)
	if err != nil {
		return err
	}

	// 2. Run smoke test.
	apoxyConfigSecret := client.SetSecret(
		"apoxy-config-yaml",
		fmt.Sprintf(apoxyConfigYAML, apoxyAPIKey),
	)
	out, err := client.Container().
		From("ubuntu:22.04").
		WithExec([]string{"apt-get", "update", "-yq"}).
		WithExec([]string{
			"apt-get", "install", "-yq", "ca-certificates",
		}).
		WithFile("/usr/local/bin/apoxy", builder.File(filepath.Join(outPath, "apoxy-cli"))).
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

	// 3. Publish Backplane image.
	_, err = client.Container().
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithFile("/bin/backplane", builder.File(filepath.Join(outPath, "backplane"))).
		WithEntrypoint([]string{"/bin/backplane"}).
		WithRegistryAuth(
			"docker.io",
			"apoxy",
			client.SetSecret("dockerhub-apoxy", os.Getenv("APOXY_DOCKERHUB_PASSWORD")),
		).
		Publish(ctx, "docker.io/apoxy/backplane:"+sha)
	if err != nil {
		return err
	}

	return nil
}
