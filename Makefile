.PHONY: help build build-fast brd brd-fast build-no-cache up up-logs down logs logs-tail restart clean clean-all shell test test-unit test-integration test-e2e test-e2e-init test-e2e-providers test-e2e-auth test-e2e-integration query status rebuild rebuild-quick watch cache-info edit-config

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
	@echo "  make build           - Run tests & build with cache"
	@echo "  make build-fast      - Run tests & fast parallel build"
	@echo "  make brd             - Run tests, build & redeploy (with logs)"
	@echo "  make brd-fast        - Ultra-fast rebuild (code only, no tests)"
	@echo "  make build-no-cache  - Run tests & build without cache"
	@echo "  make rebuild-quick   - Quick rebuild (code changes only, no tests)"
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
	@echo "  make test-unit       - Run Go unit tests"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-e2e        - Run end-to-end CLI tests (all)"
	@echo "  make test-e2e-init   - Run init tests only"
	@echo "  make test-e2e-providers - Run provider tests only"
	@echo "  make test-e2e-auth   - Run auth tests only"
	@echo "  make test-e2e-integration - Run integration tests only"
	@echo "  make test            - Test proxy connection"
	@echo "  make query           - Run sample query"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean           - Clean containers and volumes"
	@echo "  make clean-all       - Deep clean (including cache)"
	@echo "  make cache-info      - Show build cache usage"
	@echo "  make edit-config     - Edit config and restart"
	@echo ""

# Run Go unit tests
test-unit:
	@echo "Running Go unit tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "✓ All tests passed"

# Run integration tests (if you have a separate integration test suite)
test-integration:
	@echo "Running integration tests..."
	@go test -v -tags=integration ./...
	@echo "✓ Integration tests passed"

# Run end-to-end CLI tests (all) - with shared server (faster)
test-e2e:
	@echo "Running end-to-end CLI tests (shared server)..."
	@./test/e2e/run_all_shared.sh

# Run end-to-end CLI tests (all) - each test with own server (slower)
test-e2e-isolated:
	@echo "Running end-to-end CLI tests (isolated)..."
	@./test/e2e/run_all.sh

# Run individual e2e test suites
test-e2e-init:
	@echo "Running initialization tests..."
	@./test/e2e/test_init.sh

test-e2e-providers:
	@echo "Running provider lifecycle tests..."
	@./test/e2e/test_providers.sh

test-e2e-provider-config:
	@echo "Running provider configuration tests..."
	@./test/e2e/test_provider_config.sh

test-e2e-auth:
	@echo "Running auth lifecycle tests..."
	@./test/e2e/test_auth.sh

test-e2e-auth-config:
	@echo "Running auth configuration tests..."
	@./test/e2e/test_auth_config.sh

test-e2e-write:
	@echo "Running write command tests..."
	@./test/e2e/test_write.sh

test-e2e-integration:
	@echo "Running integration workflow tests..."
	@./test/e2e/test_integration.sh

# Normal build with cache (runs tests first)
build: test-unit
	@echo "Building $(IMAGE_NAME) with cache..."
	docker-compose build

# Fast parallel build (runs tests first)
build-fast: test-unit
	@echo "Building $(IMAGE_NAME) with parallel processing..."
	docker-compose build --parallel

# Build and redeploy warden only (runs tests first)
brd: test-unit
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

# Build without cache (clean build, runs tests first)
build-no-cache: test-unit
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

# Complete setup (build + up, includes tests)
setup: build up
	@echo ""
	@echo "========================================"
	@echo "Setup complete!"
	@echo "Run 'make test' to verify"
	@echo "========================================"

# Development mode (build + up with logs, includes tests)
dev: build up-logs

# Production build (optimized, runs tests first)
prod-build: test-unit
	@echo "Building for production..."
	docker build \
		--build-arg BUILDKIT_INLINE_CACHE=1 \
		--cache-from $(IMAGE_NAME):latest \
		-t $(IMAGE_NAME):latest \
		-t $(IMAGE_NAME):$(shell date +%Y%m%d) \
		.
	@echo "✓ Production build complete"

