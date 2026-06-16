module github.com/ThalesGroup/crypto11

go 1.26.1

require (
	github.com/eclipse-keypont/pkcs11-go v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.11.1
	github.com/thales-e-security/pool v0.0.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/eclipse-keypont/pkcs11-go v0.0.0 => ../pkcs11-go
