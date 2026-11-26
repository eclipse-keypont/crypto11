module github.com/eclipse-keypont/crypto11/v2

go 1.25.0

toolchain go1.27.3

require (
	github.com/eclipse-keypont/pkcs11-go v1.2.0
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

// Note: This can be removed once https://github.com/eclipse-keypont/pkcs11-go/pull/52
// is merged
replace github.com/eclipse-keypont/pkcs11-go => github.com/maraino/pkcs11-go v0.0.0-20261126041401-b314e06a91ca