# SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
# SPDX-License-Identifier: MIT

.PHONY: notices

## Licenses
notices:
	@go-licenses report ./... --ignore github.com/ThalesGroup/crypto11,github.com/eclipse-keypont/pkcs11-go --template go-licenses.tpl > NOTICES.md
	@echo "NOTICES.md generated"
