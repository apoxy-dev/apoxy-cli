FROM golang:latest as builder

WORKDIR /src

ADD . .

#RUN apt-get update -yq
#RUN apt-get install -yq xz-utils clang
#
#RUN  wget https://ziglang.org/download/0.13.0/zig-linux-aarch64-0.13.0.tar.xz \
#    tar -xf zig-linux-aarch64-0.13.0.tar.xz \
#    ln -s /src/zig-linux-aarch64-0.13.0/zig /bin/zig

ENV GOMODCACHE /go/pkg/mod
ENV GOCACHE /go/pkg/cache

RUN --mount=type=cache,target=/go/pkg/mod \
    go build -o /bin/backplane ./cmd/backplane
RUN --mount=type=cache,target=/go/pkg/cache \
    go build -o /bin/dial-stdio ./cmd/dial-stdio

FROM cgr.dev/chainguard/wolfi-base:latest

COPY --from=builder /bin/backplane /bin/backplane
COPY --from=builder /bin/dial-stdio /bin/dial-stdio

ENTRYPOINT [ "/bin/backplane" ]
