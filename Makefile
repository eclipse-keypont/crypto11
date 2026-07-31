# SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
# SPDX-License-Identifier: MIT

.PHONY: build vet test lint lint-fix govulncheck notices version release

# ── Build ────────────────────────────────────────────────────────────────────
build:
	go build ./...

# ── Vet ──────────────────────────────────────────────────────────────────────
vet:
	go vet ./...

# ── Tests ────────────────────────────────────────────────────────────────────
# Plain `go test ./...` works standalone: TestMain (setup_test.go) skips the
# HSM-backed suite cleanly when neither PKCS11_MODULE nor a pre-existing
# crypto11.config.json is present.
#
# For full coverage (including ML-KEM / PKCS#11 v3.2 tests) against SoftHSMv3:
#   PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so go test ./...
test:
	go test ./...

# ── Lint ─────────────────────────────────────────────────────────────────────
# Runs golangci-lint (v2) against .golangci.yml — the same checks as the CI
# Lint workflow, so you can catch issues before pushing.
#
# Install the linter (v2, matching CI's `version: latest`):
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Ensure $(go env GOPATH)/bin is on your PATH, then `golangci-lint version`.
GOLANGCI_LINT ?= golangci-lint

lint:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
	    echo "golangci-lint not found. Install the v2 binary with:"; \
	    echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
	    exit 1; \
	}
	$(GOLANGCI_LINT) run ./...

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
	$(GOLANGCI_LINT) run --fix ./...

# ── Vulnerability scan ───────────────────────────────────────────────────────
# Runs govulncheck (reachability-aware, cross-checked against the Go vuln DB) —
# the same check as the CI govulncheck workflow (.github/workflows/govulncheck.yml).
#
# Install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
GOVULNCHECK ?= govulncheck

govulncheck:
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { \
	    echo "govulncheck not found. Install it with:"; \
	    echo "  go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	    exit 1; \
	}
	$(GOVULNCHECK) -show verbose ./...

# ── Licenses ─────────────────────────────────────────────────────────────────
# Regenerates NOTICES.md from the module graph, rendering go-licenses.tpl.
#
# Expected on every run: klog "W... contains non-Go code that can't be inspected
# for further dependencies" warnings for pkcs11-go's cgo shim and PKCS#11
# headers. These are warnings on stderr, not errors — go-licenses resolves the
# import graph by parsing Go source and simply cannot follow .c/.h files (which
# have no Go imports to follow anyway). The target still exits 0. They cannot be
# silenced: go-licenses registers klog's --logtostderr/--stderrthreshold flags
# but ignores them, and filtering stderr here would also hide real failures.
#
# Only non-test dependencies are listed — consumers never compile *_test.go, so
# testify and its indirect deps are intentionally absent. Pass --include_tests
# to change that.
#
# Install go-licenses:
#   go install github.com/google/go-licenses@latest
GO_LICENSES ?= go-licenses

notices:
	@command -v $(GO_LICENSES) >/dev/null 2>&1 || { \
	    echo "go-licenses not found. Install it with:"; \
	    echo "  go install github.com/google/go-licenses@latest"; \
	    exit 1; \
	}
	@{ $(GO_LICENSES) report ./... --ignore github.com/eclipse-keypont/crypto11 --template go-licenses.tpl > NOTICES.md.tmp && \
	   printf '\n## Vendored source (in-tree)\n\nThe following code is copied directly into this repository and is not a Go module dependency, so it is not covered by the table above.\n\n| Path | Origin | License | License file |\n|------|--------|---------|--------------|\n| `internal/pool` | `github.com/thales-e-security/pool` (extracted from `vitess.io/vitess`) | Apache-2.0 | [internal/pool/LICENSE](internal/pool/LICENSE) |\n' >> NOTICES.md.tmp && \
	   mv NOTICES.md.tmp NOTICES.md; } || { rm -f NOTICES.md.tmp; exit 1; }
	@echo "NOTICES.md generated"

# ── Release ───────────────────────────────────────────────────────────────────
# Versioning is git-tag only — there is no in-repo version file/const to bump
# (unlike pkcs11-go, which derives its tag from cryptoki/version.go).
#
#   * Run: make release VERSION=1.7.0   (tags v1.7.0, signed, and pushes)
#   * Or:  make version                  (prints the most recent tag)
#
# The tag is created with `git tag -s` (GPG/SSH-signed, per your git signing
# config) so consumers can `git verify-tag v$VERSION`. Pushing the tag triggers
# .github/workflows/release.yml, which gates on Lint + govulncheck, then builds
# a signed source archive with SLSA3 provenance. `go get` consumers still rely
# on go.sum + sum.golang.org, not on these release assets.
version:
	@git describe --tags --abbrev=0 2>/dev/null || echo "no tags yet"

release:
	@if [ -z "$(VERSION)" ]; then \
	    echo ""; \
	    echo "Error: VERSION is not set."; \
	    echo ""; \
	    echo "Example:"; \
	    echo "  make release VERSION=1.7.0"; \
	    echo ""; \
	    exit 1; \
	fi
	git tag -s "v$(VERSION)" -m "Release v$(VERSION)"
	git push --tags
	@echo "Released v$(VERSION)"
