#/bin/bash

PACKAGE="github.com/apoxy-dev/apoxy-cli"
VERSION="$(git describe --tags --always --abbrev=0 --match='v[0-9]*.[0-9]*.[0-9]*' 2> /dev/null | sed 's/^.//')"
COMMIT_HASH="$(git rev-parse --short HEAD)"
BUILD_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

DIRTY="$(git status --porcelain)"
if [ -n "${DIRTY}" ]; then
  COMMIT_HASH="${COMMIT_HASH}-dirty"
fi

LDFLAGS=(
  "-X '${PACKAGE}/build.BuildVersion=${VERSION}'"
  "-X '${PACKAGE}/build.BuildDate=${BUILD_TIMESTAMP}'"
  "-X '${PACKAGE}/build.CommitHash=${COMMIT_HASH}'"
)

echo "Building version ${VERSION} (${COMMIT_HASH})..."

go install -ldflags="${LDFLAGS[*]}"

mv ${GOPATH}/bin/apoxy-cli ${GOPATH}/bin/apoxy
