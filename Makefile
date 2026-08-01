# LIAS & DIS Build Automation
# Version: 1.0

BINARY_DIS := dis
BINARY_LIAS := lias
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR := bin
LDFLAGS := -s -w -X main.version=$(VERSION)

# Default target
.PHONY: all
all: build

# Build both binaries for the host architecture
.PHONY: build
build: build-dis build-lias

.PHONY: build-dis
build-dis:
    @echo "Building $(BINARY_DIS)..."
    @mkdir -p $(BUILD_DIR)
    cd apps/discovery-service && CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o ../../$(BUILD_DIR)/$(BINARY_DIS) ./cmd/discovery-service

.PHONY: build-lias
build-lias:
    @echo "Building $(BINARY_LIAS)..."
    @mkdir -p $(BUILD_DIR)
    cd apps/lias && CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o ../../$(BUILD_DIR)/$(BINARY_LIAS) ./cmd/lias

# Cross-compile for linux/amd64 and linux/arm64
.PHONY: release
release: release-amd64 release-arm64

.PHONY: release-amd64
release-amd64: 
    @echo "Cross-compiling for linux/amd64..."
    @mkdir -p $(BUILD_DIR)
    cd apps/discovery-service && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o ../../$(BUILD_DIR)/$(BINARY_DIS)-amd64 ./cmd/discovery-service
    cd apps/lias && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o ../../$(BUILD_DIR)/$(BINARY_LIAS)-amd64 ./cmd/lias

.PHONY: release-arm64
release-arm64:
    @echo "Cross-compiling for linux/arm64..."
    @mkdir -p $(BUILD_DIR)
    cd apps/discovery-service && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o ../../$(BUILD_DIR)/$(BINARY_DIS)-arm64 ./cmd/discovery-service
    cd apps/lias && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o ../../$(BUILD_DIR)/$(BINARY_LIAS)-arm64 ./cmd/lias

# Run DIS locally
.PHONY: run-dis
run-dis: build-dis
    ./$(BUILD_DIR)/$(BINARY_DIS)

# Run LIAS locally
.PHONY: run-lias
run-lias: build-lias
    ./$(BUILD_DIR)/$(BINARY_LIAS)

# Clean build artifacts
.PHONY: clean
clean:
    @echo "Cleaning build directory..."
    rm -rf $(BUILD_DIR)

# Tidy go modules
.PHONY: tidy
tidy:
    cd apps/discovery-service && go mod tidy
    cd apps/lias && go mod tidy
