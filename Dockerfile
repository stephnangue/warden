# syntax=docker/dockerfile:1.4
FROM golang:1.25.1-alpine AS builder

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

# Use distroless for smallest final image
FROM gcr.io/distroless/static-debian12:nonroot AS final

WORKDIR /app

# Copy only the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/warden ./warden

EXPOSE 4000 5000

USER nonroot:nonroot

ENTRYPOINT ["./warden", "server"]
CMD ["--config", "/config/warden.hcl"]