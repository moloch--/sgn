GO ?= go
RUST_TOOLCHAIN ?= 1.94.0
CARGO ?= cargo +$(RUST_TOOLCHAIN)
CARGO_HOME_PATH ?= $(if $(CARGO_HOME),$(CARGO_HOME),$(HOME)/.cargo)

BUILD_DIR ?= build
BINARY ?= $(BUILD_DIR)/sgn
VERSION ?= $(shell git describe --tags --always --dirty)

RUST_WASM_TARGET ?= wasm32-wasip1
RUST_WASM_PROFILE ?= wasm-release
RUST_WASM_RAW := target/$(RUST_WASM_TARGET)/$(RUST_WASM_PROFILE)/sgn.wasm
RUST_WASM := target/$(RUST_WASM_TARGET)/$(RUST_WASM_PROFILE)/sgn.normalized.wasm
EMBEDDED_WASM := pkg/sgn.wasm
COMPAT_ORACLE := $(abspath target/release/examples/compat_oracle)
WASM_RUSTFLAGS := --remap-path-prefix=$(CURDIR)=/sgn --remap-path-prefix=$(CARGO_HOME_PATH)=/cargo
WASM_NORMALIZER ?= $(GO) run ./internal/cmd/wasmstrip

GO_BUILD_FLAGS := -trimpath -ldflags="-s -w -X github.com/moloch--/sgn/config.Version=$(VERSION)"
GO_TEST_FLAGS ?=

.DEFAULT_GOAL := build

# Preserve symbols through linking so rustc hosts agree on function order, then
# remove non-semantic Wasm custom sections with the repo-local normalizer.
wasm-build:
	CARGO_INCREMENTAL=0 RUSTFLAGS="$(WASM_RUSTFLAGS)" $(CARGO) build --locked --profile $(RUST_WASM_PROFILE) --target $(RUST_WASM_TARGET) --lib
	$(WASM_NORMALIZER) -o $(RUST_WASM) $(RUST_WASM_RAW)

# Refresh the tracked module embedded by pkg/wasm.go after changing Rust code.
wasm-update: wasm-build
	cp $(RUST_WASM) $(EMBEDDED_WASM)

# Rebuild independently and fail if the tracked embedded module is stale.
wasm-verify: wasm-build
	cmp $(RUST_WASM) $(EMBEDDED_WASM) || { \
		echo "$(EMBEDDED_WASM) is stale; run 'make wasm-update' and commit it" >&2; \
		exit 1; \
	}

go-build: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) .

build: go-build

# Preserve the historical default target name.
default: build

static: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -o $(BINARY) .

test-rust:
	$(CARGO) test --locked

test-go: wasm-verify
	$(GO) test $(GO_TEST_FLAGS) ./...

# Compare native Rust and embedded Rust/Wasm byte-for-byte under fixed seeds.
test-compat: wasm-verify
	$(CARGO) build --locked --release --example compat_oracle
	SGN_NATIVE_ORACLE="$(COMPAT_ORACLE)" $(GO) test ./pkg -run '^(TestNativeRustWASMCompatibility|TestUpstreamRustGoldenVector)$$' -count=1

test: test-rust test-go test-compat

386: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOARCH=386 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) .

linux_amd64: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) .

linux_386: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) .

windows_amd64: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/sgn.exe .

windows_386: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=386 $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/sgn32.exe .

darwin_amd64: wasm-verify
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) .

clean:
	$(CARGO) clean
	rm -rf ./build

.PHONY: \
	build clean darwin_amd64 default go-build linux_386 linux_amd64 static test \
	test-compat test-go test-rust wasm-build wasm-update wasm-verify windows_386 \
	windows_amd64 386
