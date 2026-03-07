.PHONY: generate lint test test-qemu install-qemu-deps

generate:
	git submodule update --init
	go generate ./pkg/gen/

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run ./...

test:
	go test ./...

# QEMU E2E tests (requires qemu-system-x86_64 and a Linux kernel)
test-qemu:
	go test ./tests/qemu/ -v -tags=qemu -timeout=300s -count=1

# Install kernel and QEMU for QEMU tests (Ubuntu/Debian)
install-qemu-deps:
	sudo apt-get update
	sudo apt-get install -y qemu-system-x86 linux-image-generic
