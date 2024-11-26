# Apoxy Images

## Build Locally

### Apoxy API Server

```shell
dagger call build-apiserver --src=. export --path=dist/images/apiserver.tar
```

To import the image into your local Docker daemon:

```shell
skopeo copy oci-archive:dist/images/apiserver.tar docker-daemon:docker.io/apoxy/apiserver:latest
```

### Apoxy Backplane

```shell
dagger call build-backplane --platform=linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') --src=. export --path=dist/images/backplane.tar
```

To import the image into your local Docker daemon:

```shell
skopeo copy oci-archive:dist/images/backplane.tar docker-daemon:docker.io/apoxy/backplane:latest
```
