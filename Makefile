# SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
# SPDX-License-Identifier: MIT

.PHONY: build vet test fuzz lint lint-fix govulncheck notices sbom version release

# ── Tool preconditions ───────────────────────────────────────────────────────
# $(call require,<binary>,<how to install it>) — fail early with an install hint.
#
# Probes by running the tool, not `command -v`: a goenv shim stays on PATH even
# when the tool is not installed for the active Go version, so `command -v` says
# yes and the build dies later. Exit 127 (missing binary or dead shim) is the
# only status treated as missing; tools without --version exit 1 or 2 and pass.
#
# A hint must not contain a comma — make would read it as another $(call) argument.
define require
@$(1) --version >/dev/null 2>&1; \
if [ $$? -eq 127 ]; then \
    echo "$(1) not found. Install it with:"; \
    echo "  $(2)"; \
    exit 1; \
fi
endef

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

# ── Fuzzing ──────────────────────────────────────────────────────────────────
# Runs each fuzz target in fuzz_test.go in turn, for FUZZTIME each. No PKCS#11
# module is needed: the targets parse bytes off the token and TestMain narrows
# the run to them when no token is configured.
#
#   make fuzz                          # every target, 30s each
#   make fuzz FUZZTIME=5m              # longer budget
#   make fuzz FUZZ=FuzzKMACEncodings   # one target
#
# The seed corpora already run as part of `make test`; this is the open-ended
# search on top of them. A failing input lands in testdata/fuzz/<Target>/ —
# commit it, and `make test` replays it from then on.
FUZZTIME ?= 30s
FUZZ ?=
# Target names are read out of the file rather than listed here, so a new target
# is picked up by adding it. The awk/sed pair avoids parentheses, which make
# would try to balance inside $(shell ...).
FUZZ_TARGETS := $(if $(FUZZ),$(FUZZ),$(shell awk '/^func Fuzz/ {print $$2}' fuzz_test.go | sed 's/[^A-Za-z0-9_].*//'))

fuzz:
	@for target in $(FUZZ_TARGETS); do \
	    echo "── $$target ($(FUZZTIME)) ──"; \
	    go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) . || exit 1; \
	done

# ── Lint ─────────────────────────────────────────────────────────────────────
# Runs golangci-lint (v2) against .golangci.yml — the same checks as the CI
# Lint workflow, so you can catch issues before pushing.
#
# Install the linter (v2, matching CI's `version: latest`):
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Ensure $(go env GOPATH)/bin is on your PATH, then `golangci-lint version`.
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_INSTALL_HINT := go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint:
	$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
	$(GOLANGCI_LINT) run ./...

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
	$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
	$(GOLANGCI_LINT) run --fix ./...

# ── Vulnerability scan ───────────────────────────────────────────────────────
# Runs govulncheck (reachability-aware, cross-checked against the Go vuln DB) —
# the same check as the CI govulncheck workflow (.github/workflows/govulncheck.yml).
#
# Install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
GOVULNCHECK ?= govulncheck

govulncheck:
	$(call require,$(GOVULNCHECK),go install golang.org/x/vuln/cmd/govulncheck@latest)
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
	$(call require,$(GO_LICENSES),go install github.com/google/go-licenses@latest)
	@{ $(GO_LICENSES) report ./... --ignore github.com/eclipse-keypont/crypto11 --template go-licenses.tpl > NOTICES.md.tmp && \
	   printf '\n## Vendored source (in-tree)\n\nThe following code is copied directly into this repository and is not a Go module dependency, so it is not covered by the table above.\n\n| Path | Origin | License | License file |\n|------|--------|---------|--------------|\n| `internal/pool` | `github.com/thales-e-security/pool` (extracted from `vitess.io/vitess`) | Apache-2.0 | [internal/pool/LICENSE](internal/pool/LICENSE) |\n' >> NOTICES.md.tmp && \
	   mv NOTICES.md.tmp NOTICES.md; } || { rm -f NOTICES.md.tmp; exit 1; }
	@echo "NOTICES.md generated"

# ── SBOM ─────────────────────────────────────────────────────────────────────
# Generates a CycloneDX 1.6 SBOM with the exact same flags as the release
# workflow (.github/workflows/release.yml), so an auditor can regenerate the
# published crypto11-vX.Y.Z.cdx.json from the tagged source and compare hashes.
#
# -std includes the Go standard library as a component (stdlib CVEs stay visible
# to SBOM consumers); -licenses records detected licenses as evidence; test-only
# dependencies are excluded — they are not part of what consumers link against.
# -noserial -notimestamp drop the two nondeterministic fields, making the output
# byte-reproducible for a given tag on a given GOOS/GOARCH (purls carry
# goos/goarch qualifiers, so regenerate on linux/amd64 to match the release).
#
# Install cyclonedx-gomod (same version as CI):
#   go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0
CYCLONEDX_GOMOD ?= cyclonedx-gomod
SBOM_FILE       ?= crypto11.cdx.json

sbom:
	$(call require,$(CYCLONEDX_GOMOD),go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0)
	$(CYCLONEDX_GOMOD) mod -json -licenses -std -type library \
	    -noserial -notimestamp -output $(SBOM_FILE) .
	@echo "$(SBOM_FILE) generated"

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
# a signed source archive and a signed CycloneDX SBOM, both covered by SLSA3
# provenance. `go get` consumers still rely on go.sum + sum.golang.org, not on
# these release assets.
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
