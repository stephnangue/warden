# syntax=docker/dockerfile:1.4
FROM golang:1.26.7-alpine AS builder

# Install build dependencies in a single layer
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum first for better layer caching
COPY go.mod go.sum ./


# Download dependencies with cache mounts - this layer is cached until go.mod/go.sum changes
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download -x

# Copy only necessary source files (respects .dockerignore)
COPY . .

# Build with optimizations and cache mounts
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -v -trimpath \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o warden .

# The distroless base has no shell, so the directories the image ships are
# built in a throwaway stage. /var/log/warden and /certs are owned by nonroot:
# a new named volume mounted there takes that ownership, so the audit device
# and -dev-tls-cert-dir can write without a manual chown.
FROM busybox:1.36 AS dirs
RUN mkdir -p -m 0755 /out/config /out/var/log/warden /out/certs \
 && chown 65532:65532 /out/var/log/warden /out/certs

# Use distroless for smallest final image
FROM gcr.io/distroless/static-debian12:nonroot AS final

COPY --from=dirs /out/ /

WORKDIR /app

# Copy only the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/warden ./warden

# Dev mode binds loopback by default, which a published port cannot reach
# inside a container. Config-file mode ignores this.
ENV WARDEN_DEV_LISTEN_ADDRESS=0.0.0.0:8400

EXPOSE 8400 8401

USER nonroot:nonroot

ENTRYPOINT ["./warden", "server"]
CMD ["--config", "/config/warden.hcl"]