# Third-Party Notices

This project uses the following third-party Go modules.

| Package | License | License URL |
|---------|---------|-------------|
| `github.com/eclipse-keypont/pkcs11-go` | MIT | [Link](https://github.com/eclipse-keypont/pkcs11-go/blob/v1.2.0/LICENSE) |

## Test-only dependencies

The following modules are used only by the test suite. They are not compiled into the released artifact and are therefore not part of what consumers link against.

| Package | License | License URL |
|---------|---------|-------------|
| `github.com/stretchr/testify` | MIT | [Link](https://github.com/stretchr/testify/blob/v1.12.1/LICENSE) |
| `github.com/stretchr/testify/internal/difflib` | BSD-3-Clause | [Link](https://github.com/stretchr/testify/blob/v1.12.1/internal/difflib/LICENSE) |
| `github.com/stretchr/testify/internal/spew` | ISC | [Link](https://github.com/stretchr/testify/blob/v1.12.1/internal/spew/LICENSE) |
| `go.yaml.in/yaml/v3` | MIT | [Link](https://github.com/yaml/go-yaml/blob/v3.0.5/LICENSE) |

## Vendored source (in-tree)

The following code is copied directly into this repository and is not a Go module dependency, so it is not covered by the table above.

| Path | Origin | License | License file |
|------|--------|---------|--------------|
| `internal/pool` | `github.com/thales-e-security/pool` (extracted from `vitess.io/vitess`) | Apache-2.0 | [internal/pool/LICENSE](internal/pool/LICENSE) |
