# Makefile for building static linux/amd64 binary using cargo with musl

BINARY_NAME = github-authorized-secrets
TARGET = x86_64-unknown-linux-musl
BUILD_DIR = target/$(TARGET)/release
OUTPUT_BINARY = $(BINARY_NAME)-linux-amd64

.PHONY: build clean help

# Default target
build: $(OUTPUT_BINARY)

# Build the linux binary using cargo with musl cross-compilation
$(OUTPUT_BINARY): src/main.rs Cargo.toml Cargo.lock
	@echo "Building static linux/amd64 binary with musl..."
	@echo "Setting up musl cross-compilation environment..."
	CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc \
	cargo build --release --target $(TARGET)
	@echo "Copying binary to repo root..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(OUTPUT_BINARY)
	@echo "Built: $(OUTPUT_BINARY)"

# Clean build artifacts and output binary
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	@if [ -f $(OUTPUT_BINARY) ]; then \
		rm $(OUTPUT_BINARY); \
		echo "Removed $(OUTPUT_BINARY)"; \
	fi

# Show help
help:
	@echo "Available targets:"
	@echo "  build         - Build static linux/amd64 binary using cargo with musl (default)"
	@echo "  clean         - Clean build artifacts and output binary"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Output: $(OUTPUT_BINARY)"
