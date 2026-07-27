// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/sha3"
	"fmt"
)

// mlkemCekSize is the AES key size, in bytes, MLKEMDeriveKey produces for each ML-KEM
// parameter set: 128-bit for ML-KEM-512 (matching its native ~128-bit classical security
// level), 256-bit for ML-KEM-768/1024.
var mlkemCekSize = map[MLKEMParameterSet]int{
	MLKEM512:  16, // 128 bits
	MLKEM768:  32, // 256 bits
	MLKEM1024: 32, // 256 bits
}

// mlkemAlgorithmID is a fixed, parameter-set-specific string mixed into the KMAC context
// (the "X" input below) for domain separation between parameter sets. The exact bytes are
// not required to match any external registry — callers are expected to keep the derived
// key within their own envelope/protocol rather than interop on these bytes directly.
var mlkemAlgorithmID = map[MLKEMParameterSet]string{
	MLKEM512:  "crypto11/ML-KEM-512",
	MLKEM768:  "crypto11/ML-KEM-768",
	MLKEM1024: "crypto11/ML-KEM-1024",
}

// MLKEMDeriveKey derives an AES key from an ML-KEM shared secret (as returned by
// MLKEMSharedSecret.Bytes, following Encapsulate or Decapsulate) using KMAC, per NIST
// SP 800-185. paramSet must match the parameter set the shared secret was produced under;
// it selects both the output key size and the KMAC variant (KMAC128 for ML-KEM-512,
// KMAC256 for ML-KEM-768/1024) and binds the derivation to that parameter set so that
// encapsulation/decapsulation under a different parameter set can never collide.
//
// Parameters per NIST SP 800-185:
//   - K (key):        sharedSecret
//   - X (data):       be32(len(alg)) || alg || be32(outputLen*8)  — AlgorithmID || SuppPubInfo
//   - L (outputLen):  key size in bytes (16 or 32), from mlkemCekSize
//   - S (customization): empty string
func MLKEMDeriveKey(paramSet MLKEMParameterSet, sharedSecret []byte) ([]byte, error) {
	outputLen, ok := mlkemCekSize[paramSet]
	if !ok {
		return nil, fmt.Errorf("crypto11: unsupported ML-KEM parameter set %d", paramSet)
	}

	algBytes := []byte(mlkemAlgorithmID[paramSet])
	x := make([]byte, 0, 4+len(algBytes)+4)
	x = appendBE32(x, uint32(len(algBytes)))
	x = append(x, algBytes...)
	x = appendBE32(x, uint32(outputLen*8))

	if paramSet == MLKEM512 {
		return kmac128(sharedSecret, x, outputLen), nil
	}
	return kmac256(sharedSecret, x, outputLen), nil
}

// appendBE32 appends v as a big-endian 32-bit unsigned integer to b.
func appendBE32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// kmac128 computes KMAC128(K=key, X=data, L=outputLen bytes, S="") per NIST SP 800-185.
// Built on top of cSHAKE128 from the Go standard library (crypto/sha3, Go 1.24+).
func kmac128(key, data []byte, outputLen int) []byte {
	// KMAC128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(L*8), L, "KMAC", S="")
	h := sha3.NewCSHAKE128([]byte("KMAC"), nil)
	_, _ = h.Write(bytepad(encodeString(key), 168))    // never returns an error
	_, _ = h.Write(data)                               // never returns an error
	_, _ = h.Write(rightEncode(uint64(outputLen * 8))) // never returns an error
	out := make([]byte, outputLen)
	_, _ = h.Read(out) // XOF Read never returns an error
	return out
}

// kmac256 computes KMAC256(K=key, X=data, L=outputLen bytes, S="") per NIST SP 800-185.
// Built on top of cSHAKE256 from the Go standard library (crypto/sha3, Go 1.24+).
func kmac256(key, data []byte, outputLen int) []byte {
	// KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L*8), L, "KMAC", S="")
	h := sha3.NewCSHAKE256([]byte("KMAC"), nil)
	_, _ = h.Write(bytepad(encodeString(key), 136))    // never returns an error
	_, _ = h.Write(data)                               // never returns an error
	_, _ = h.Write(rightEncode(uint64(outputLen * 8))) // never returns an error
	out := make([]byte, outputLen)
	_, _ = h.Read(out) // XOF Read never returns an error
	return out
}

// --- NIST SP 800-185 encoding primitives ---

// leftEncode encodes x as a left-encoded byte string per NIST SP 800-185 Section 2.3.
// The length of the encoding (in bytes) is prepended as a single byte.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}
	var buf [8]byte
	n := 7
	for ; n >= 0 && x > 0; n-- {
		buf[n] = byte(x)
		x >>= 8
	}
	b := buf[n+1:]
	result := make([]byte, 1+len(b))
	result[0] = byte(len(b))
	copy(result[1:], b)
	return result
}

// rightEncode encodes x as a right-encoded byte string per NIST SP 800-185 Section 2.3.
// The length of the encoding (in bytes) is appended as a single byte.
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0, 1}
	}
	var buf [8]byte
	n := 7
	for ; n >= 0 && x > 0; n-- {
		buf[n] = byte(x)
		x >>= 8
	}
	b := buf[n+1:]
	result := make([]byte, len(b)+1)
	copy(result, b)
	result[len(b)] = byte(len(b))
	return result
}

// encodeString encodes a byte string S as left_encode(len(S)*8) || S per NIST SP 800-185 Section 2.3.
func encodeString(s []byte) []byte {
	return append(leftEncode(uint64(len(s))*8), s...)
}

// bytepad pads X to the next multiple of w bytes, prepended with left_encode(w),
// per NIST SP 800-185 Section 2.3.
func bytepad(x []byte, w int) []byte {
	z := append(leftEncode(uint64(w)), x...)
	for len(z)%w != 0 {
		z = append(z, 0)
	}
	return z
}
