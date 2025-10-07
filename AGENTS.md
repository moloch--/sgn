# Repository Guidelines

## Project Structure & Module Organization
- `main.go` contains the CLI entry point; it wires flags, loads payloads, and calls the encoder.
- `pkg/` hosts reusable packages (e.g., encoder logic, keystone bindings) intended for import from both the CLI and future tools.
- `test/` holds payload samples and fixtures used by integration-style tests; keep new fixtures small and clearly named.
- `img/` stores documentation assets only—do not check binaries or test data here.

## Build, Test, and Development Commands
- `make normal` — builds the macOS/Linux host binary as `./sgn` with release flags.
- `make darwin` / `make linux_amd64` / `make windows_amd64` — cross-compiles with the correct `CGO_LDFLAGS`; ensure the Keystone SDK is pre-installed on runners.
- `/opt/homebrew/bin/go build ./...` — fast local sanity build; always use the pinned toolchain path.
- `/opt/homebrew/bin/go test ./...` — runs unit and integration tests; add `-count=1` when validating changes dependent on randomness.
- `go run main.go -h` — quick smoke-test of CLI flag parsing after edits.

## Coding Style & Naming Conventions
- Follow standard Go style (`gofmt` on save); idiomatic camelCase for locals and exported PascalCase for public symbols.
- Keep files ASCII; include short doc comments (`// Package encoder ...`) on exported packages, types, and functions.
- Group CGO-related constants and `CGO_LDFLAGS` near usage, and note non-default toolchains in comments.

## Testing Guidelines
- Prefer table-driven tests for encoder behaviors; name functions `TestFeatureScenario`.
- Place larger payload fixtures under `testdata/` and load them within tests using `os.ReadFile`.
- Aim to cover both 32- and 64-bit encodings; add regression tests when fixing decoding bugs.
- Run `/opt/homebrew/bin/go test ./...` before pushing; CI expects a clean exit and no race detector noise.

## Commit & Pull Request Guidelines
- Write imperative, scoped commit subjects (e.g., `Add arm64 keystone build helper`) followed by a blank line and concise body when needed.
- Reference GitHub issues with `Fixes #123` when closing bugs; include brief context for encoder or workflow changes.
- For pull requests, summarize behavior changes, note build/test commands run, and link workflow runs or screenshots for UI artifacts.
- Ensure CI workflows succeed across macOS, Linux, and Windows jobs before requesting review or merging.
