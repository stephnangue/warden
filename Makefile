.PHONY: help build build-fast brd brd-fast build-no-cache up up-logs down logs logs-tail restart clean clean-all shell test query status rebuild rebuild-quick watch cache-info edit-config

# Enable BuildKit for faster builds
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

IMAGE_NAME ?= warden
CONTAINER_NAME ?= warden

help:
	@echo "========================================"
	@echo "Warden - Development"
	@echo "========================================"
	@echo ""
	@echo "Build Commands:"
	@echo "  make build           - Build with cache (normal)"
	@echo "  make build-fast      - Fast parallel build"
	@echo "  make brd             - Build & redeploy warden (with logs)"
	@echo "  make brd-fast        - Ultra-fast rebuild (code only)"
	@echo "  make build-no-cache  - Build without cache"
	@echo "  make rebuild-quick   - Quick rebuild (code changes only)"
	@echo ""
	@echo "Run Commands:"
	@echo "  make up              - Start warden proxy"
	@echo "  make up-logs         - Start with logs visible"
	@echo "  make down            - Stop warden proxy"
	@echo "  make restart         - Restart proxy"
	@echo ""
	@echo "Logs & Debug:"
	@echo "  make logs            - View logs (follow)"
	@echo "  make logs-tail       - View last 100 lines"
	@echo "  make watch           - Watch logs with tail"
	@echo "  make status          - Show container status"
	@echo "  make shell           - Shell into container"
	@echo ""
	@echo "Testing:"
	@echo "  make test            - Test proxy connection"
	@echo "  make query           - Run sample query"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean           - Clean containers and volumes"
	@echo "  make clean-all       - Deep clean (including cache)"
	@echo "  make cache-info      - Show build cache usage"
	@echo "  make edit-config     - Edit config and restart"
	@echo ""

# Normal build with cache
build:
	@echo "Building $(IMAGE_NAME) with cache..."
	docker-compose build

# Fast parallel build
build-fast:
	@echo "Building $(IMAGE_NAME) with parallel processing..."
	docker-compose build --parallel

# Build and redeploy warden only (fast rebuild)
brd:
	@echo "Fast rebuilding and redeploying warden..."
	@docker-compose build --progress=plain warden
	@docker-compose up -d warden
	@echo "✓ Warden rebuilt and deployed"
	@docker-compose logs -f $(CONTAINER_NAME)

# Ultra-fast rebuild (code changes only - no logs)
brd-fast:
	@echo "⚡ Ultra-fast rebuild (code changes only)..."
	@docker-compose build -q warden
	@docker-compose up -d warden
	@echo "✓ Done! Use 'make logs' to view output"

# Live development mode with hot reload
dev-watch:
	@echo "🔄 Starting live development mode..."
	@echo "Watching for file changes... (Press Ctrl+C to stop)"
	@while true; do \
		$(MAKE) brd-fast 2>/dev/null; \
		inotifywait -qre close_write --exclude '(\.git|\.swp|\.log|warden$$)' . 2>/dev/null || \
		fswatch -o -1 --exclude='\.git' --exclude='\.log' --exclude='warden$$' . 2>/dev/null || \
		sleep 5; \
	done

# Build without cache (clean build)
build-no-cache:
	@echo "Building $(IMAGE_NAME) without cache..."
	docker-compose build --no-cache --pull

# Quick rebuild for code changes only
rebuild-quick:
	@echo "Quick rebuild (code changes only)..."
	docker-compose build $(CONTAINER_NAME)

# Start warden proxy
up:
	docker-compose up -d

# Start with logs
up-logs:
	docker-compose up

# Stop warden proxy
down:
	@echo "Stopping warden proxy..."
	docker-compose down
	@echo "✓ Stopped"

reup:
	docker-compose down
	docker-compose up -d

# View logs (follow mode)
logs:
	docker-compose logs -f $(CONTAINER_NAME)

vault-logs:
	docker-compose logs -f vault-init


# View last 100 lines of logs
logs-tail:
	docker-compose logs --tail=100 $(CONTAINER_NAME)

# Watch logs with tail
watch:
	docker-compose logs -f --tail=100 $(CONTAINER_NAME)

# Restart proxy
restart:
	@echo "Restarting warden..."
	docker-compose restart $(CONTAINER_NAME)
	@sleep 2
	@echo "✓ Restarted"

# Clean containers and volumes
clean:
	@echo "Cleaning up..."
	docker-compose down -v
	@echo "✓ Cleaned"

# Deep clean including build cache
clean-all:
	@echo "Deep cleaning (including build cache)..."
	docker-compose down -v
	docker builder prune -af
	docker system prune -af
	@echo "✓ Deep clean completed"

# Shell into container
shell:
	docker exec -it warden sh

# Test connection
test:
	@echo "Testing warden proxy connection..."
	mysql -h 127.0.0.1 -P 4000 -u proxy -pproxy123 -e "SHOW DATABASES;"

# Test from another container
test-container:
	docker run -it --rm --network warden-network mysql:8.0 \
		mysql -h warden -P 4000 -u proxy -pproxy123 -e "SHOW DATABASES;"

# Run a query
query:
	@echo "SELECT * FROM users;" | mysql -h 127.0.0.1 -P 4000 -u proxy -pproxy123 myapp

# Show status
status:
	docker-compose ps

# Show build cache usage
cache-info:
	@echo "Docker Build Cache Usage:"
	@docker buildx du 2>/dev/null || docker system df

# Show Docker stats
stats:
	@echo "Container Resource Usage:"
	docker stats --no-stream $(CONTAINER_NAME)

# Follow logs and grep for errors
logs-errors:
	docker-compose logs -f $(CONTAINER_NAME) | grep -i error

# Complete setup (build + up)
setup: build up
	@echo ""
	@echo "========================================"
	@echo "Setup complete!"
	@echo "Run 'make test' to verify"
	@echo "========================================"

# Development mode (build + up with logs)
dev: build up-logs

# Production build (optimized)
prod-build:
	@echo "Building for production..."
	docker build \
		--build-arg BUILDKIT_INLINE_CACHE=1 \
		--cache-from $(IMAGE_NAME):latest \
		-t $(IMAGE_NAME):latest \
		-t $(IMAGE_NAME):$(shell date +%Y%m%d) \
		.
	@echo "✓ Production build complete"

