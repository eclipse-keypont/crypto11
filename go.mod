module github.com/ThalesGroup/crypto11

go 1.26.1

require (
	github.com/miekg/pkcs11 v1.1.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.11.1
	github.com/thales-e-security/pool v0.0.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// TODO(temporary): local replace for PKCS#11 v3.2 / ML-KEM support (github.com/Nicolas-Peiffer/pkcs11
// fork). Remove once upstream github.com/miekg/pkcs11 merges these changes, or once the fork's
// go.mod is updated to declare "module github.com/Nicolas-Peiffer/pkcs11".
replace github.com/miekg/pkcs11 v1.1.2 => ../pkcs11.github.com.miekg
