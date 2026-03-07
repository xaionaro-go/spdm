# Reference Testing: go-spdm against DMTF libspdm (spdm-emu)
#
# This builds the DMTF spdm-emu reference implementation and runs
# interop tests between our Go implementation and libspdm.
#
# Usage:
#   make docker-test   - build + run tests in Docker (recommended)
#   make docker-build  - build Docker image only
#   make build         - build spdm-emu locally (needs cmake, gcc, libssl-dev)
#   make test          - run interop tests locally (assumes spdm-emu is built)
#   make clean         - remove build artifacts

SHELL := /bin/bash
.PHONY: all build test clean clone coverage docker-build docker-test docker-coverage

SPDM_EMU_DIR := $(CURDIR)/spdm-emu
SPDM_EMU_BUILD := $(SPDM_EMU_DIR)/build
SPDM_EMU_BIN := $(SPDM_EMU_BUILD)/bin
GO_ROOT := $(CURDIR)/../..
COVERAGE_DIR := $(CURDIR)/coverage
SPDM_EMU_REPO := https://github.com/DMTF/spdm-emu.git
DOCKER_IMAGE := go-spdm-reference-test
DOCKER_CONTAINER := go-spdm-reference-run

# Default port for spdm-emu (platform port)
SPDM_PORT := 2323

all: docker-test

# --- Docker targets (recommended) ---

# Build the Docker image with spdm-emu and Go test environment.
docker-build:
	@echo "==> Building Docker image (this clones + compiles spdm-emu)..."
	cd $(GO_ROOT) && docker build \
		-t $(DOCKER_IMAGE) \
		-f tests/reference/Dockerfile \
		.

# Run reference interop tests inside Docker and extract coverage.
docker-test: docker-build
	@echo "==> Running reference interop tests in Docker..."
	@mkdir -p $(COVERAGE_DIR)
	docker rm -f $(DOCKER_CONTAINER) 2>/dev/null || true
	docker run --name $(DOCKER_CONTAINER) $(DOCKER_IMAGE) || \
		(echo "==> Tests failed. Logs:"; docker logs $(DOCKER_CONTAINER); exit 1)
	docker cp $(DOCKER_CONTAINER):/tmp/reference-coverage.out $(COVERAGE_DIR)/reference.cov 2>/dev/null || true
	docker rm -f $(DOCKER_CONTAINER) 2>/dev/null || true
	@echo "==> Done. Coverage saved to $(COVERAGE_DIR)/reference.cov"

# Show coverage from Docker test run.
docker-coverage: docker-test
	@echo "==> Coverage from reference tests:"
	cd $(GO_ROOT) && go tool cover -func=$(COVERAGE_DIR)/reference.cov | tail -1
	cd $(GO_ROOT) && go tool cover -func=$(COVERAGE_DIR)/reference.cov

# --- Local targets (requires cmake, gcc, libssl-dev) ---

# Clone spdm-emu if not present.
clone:
	@if [ ! -d "$(SPDM_EMU_DIR)" ]; then \
		echo "==> Cloning spdm-emu..."; \
		git clone --recursive $(SPDM_EMU_REPO) $(SPDM_EMU_DIR); \
	else \
		echo "==> spdm-emu already cloned"; \
	fi

# Build spdm-emu with OpenSSL crypto backend.
build: clone
	@echo "==> Building spdm-emu..."
	@mkdir -p $(SPDM_EMU_BUILD)
	cd $(SPDM_EMU_BUILD) && cmake \
		-DARCH=x64 \
		-DTOOLCHAIN=GCC \
		-DTARGET=Release \
		-DCRYPTO=openssl \
		..
	cd $(SPDM_EMU_BUILD) && make copy_sample_key
	cd $(SPDM_EMU_BUILD) && make -j$$(nproc)
	@echo "==> Build complete. Binaries in $(SPDM_EMU_BIN)"
	@ls -la $(SPDM_EMU_BIN)/spdm_responder_emu $(SPDM_EMU_BIN)/spdm_requester_emu 2>/dev/null || true

# Run interop tests locally.
test:
	@echo "==> Running reference interop tests..."
	@mkdir -p $(COVERAGE_DIR)
	cd $(GO_ROOT) && go test ./tests/reference/interop/ \
		-v \
		-count=1 \
		-timeout=120s \
		-coverprofile=$(COVERAGE_DIR)/reference.cov \
		-coverpkg=$$(cd $(GO_ROOT) && go list ./pkg/... | grep -v '/gen/' | paste -sd, -) \
		-tags=reference \
		-args \
			-spdm-emu-bin=$(SPDM_EMU_BIN) \
			-spdm-port=$(SPDM_PORT)

# Show coverage from local test run.
coverage: test
	@echo "==> Coverage from reference tests:"
	cd $(GO_ROOT) && go tool cover -func=$(COVERAGE_DIR)/reference.cov | tail -1
	cd $(GO_ROOT) && go tool cover -func=$(COVERAGE_DIR)/reference.cov

clean:
	rm -rf $(SPDM_EMU_DIR) $(COVERAGE_DIR)
	docker rm -f $(DOCKER_CONTAINER) 2>/dev/null || true
	docker rmi -f $(DOCKER_IMAGE) 2>/dev/null || true
