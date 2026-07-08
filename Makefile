# SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
# SPDX-License-Identifier: MIT

.PHONY: notices

## Licenses
notices:
	@go-licenses report ./... --ignore github.com/eclipse-keypont/crypto11,github.com/eclipse-keypont/pkcs11-go --template go-licenses.tpl > NOTICES.md
	@printf '\n## Vendored source (in-tree)\n\nThe following code is copied directly into this repository and is not a Go module dependency, so it is not covered by the table above.\n\n| Path | Origin | License | License file |\n|------|--------|---------|--------------|\n| `internal/pool` | `github.com/thales-e-security/pool` (extracted from `vitess.io/vitess`) | Apache-2.0 | [internal/pool/LICENSE](internal/pool/LICENSE) |\n' >> NOTICES.md
	@echo "NOTICES.md generated"
