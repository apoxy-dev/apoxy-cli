# Dagger Deploy on Fly

## Generate mTLS Certificates

```bash
mkdir -p secrets
```

```bash
# Generate CA
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -days 3650 -subj "/CN=dagger.apoxy.dev/O=Apoxy, Inc./C=US" \
    -keyout secrets/ca.key -out secrets/ca.crt
```

```bash
# Generate Server Cert
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -subj "/CN=dagger.apoxy.dev/O=Apoxy, Inc./C=US" \
    -keyout secrets/server.key -out secrets/server.csr
openssl x509 -req -in secrets/server.csr \
    -CA secrets/ca.crt -CAkey secrets/ca.key -CAcreateserial \
    -out secrets/server.crt -days 3650 -extensions v3_req \
    -extfile <(printf "[v3_req]\nsubjectAltName=DNS:dagger.apoxy.dev")
```

```bash
# Generate Client Cert
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -subj "/CN=dagger-client.apoxy.dev/O=Apoxy, Inc./C=US" \
    -keyout secrets/client.key -out secrets/client.csr
openssl x509 -req -in secrets/client.csr \
    -CA secrets/ca.crt -CAkey secrets/ca.key -CAcreateserial \
    -out secrets/client.crt -days 3650 -extensions v3_req \
    -extfile <(printf "[v3_req]\nsubjectAltName=DNS:dagger-client.apoxy.dev")
```

## Provision Secrets in Fly

```bash
# Create secrets
fly secrets set DAGGER_CA="$(base64 -i secrets/ca.crt)" --stage
fly secrets set SERVER_CERT="$(base64 -i secrets/server.crt)" --stage
fly secrets set SERVER_KEY="$(base64 -i secrets/server.key)" --stage
```

## Provision Secrets in GitHub

```bash
# Create secrets
gh secret set DAGGER_CA --body secrets/ca.crt
gh secret set DAGGER_CLIENT_CERT --body secrets/client.crt
gh secret set DAGGER_CLIENT_KEY --body secrets/client.key
```

## Deploy Fly App

```bash
fly app create
fly deploy
```

## Connect and Run Dagger Pipeline

```bash
# Connect to server using mTLS
func-e run -c dagger-client.yaml
```

```bash
_EXPERIMENTAL_DAGGER_RUNNER_HOST=tcp://localhost:9080 dagger --debug run go run ci/main.go
```

## Cleanup

```bash
rm -rf secrets
```

Ensure Fly Machine is stopped between runs:
```bash
fly m list
1 machines have been retrieved from app apoxy-cli-dagger.
View them in the UI here (​https://fly.io/apps/apoxy-cli-dagger/machines/)

apoxy-cli-dagger
ID            	NAME          	STATE  	REGION	IMAGE        	IP ADDRESS                     	VOLUME              	CREATED             	LAST UPDATED        	APP PLATFORMPROCESS GROUP	SIZE
e2866e09fe0368	bold-river-922	stopped	sjc   	engine:v0.9.4	fdaa::123	vol_24owwdgmey7mdd2v	2023-12-22T21:39:47Z	2023-12-22T22:43:01Z	v2          app          	shared-cpu-2x:2048MB
```
