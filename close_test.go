// Copyright 2024 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"crypto/dsa"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestErrorAfterClosed(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	err = ctx.Close()
	require.NoError(t, err)

	bytes := randomBytes()

	_, err = ctx.FindKey(bytes, nil)
	assert.Equal(t, errClosed, err)

	_, err = ctx.FindKeys(bytes, nil)
	assert.Equal(t, errClosed, err)

	_, err = ctx.FindKeysWithAttributes(NewAttributeSet())
	assert.Equal(t, errClosed, err)

	_, err = ctx.FindKeyPair(bytes, nil)
	assert.Equal(t, errClosed, err)

	_, err = ctx.FindKeyPairs(bytes, nil)
	assert.Equal(t, errClosed, err)

	_, err = ctx.FindKeyPairsWithAttributes(NewAttributeSet())
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateSecretKey(bytes, 256, CipherAES)
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateSecretKeyWithLabel(bytes, bytes, 256, CipherAES)
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateRSAKeyPair(bytes, 2048)
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateRSAKeyPairWithLabel(bytes, bytes, 2048)
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateDSAKeyPair(bytes, dsaSizes[dsa.L1024N160])
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateDSAKeyPairWithLabel(bytes, bytes, dsaSizes[dsa.L1024N160])
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateECDSAKeyPair(bytes, elliptic.P224())
	assert.Equal(t, errClosed, err)

	_, err = ctx.GenerateECDSAKeyPairWithLabel(bytes, bytes, elliptic.P224())
	assert.Equal(t, errClosed, err)

	_, err = ctx.NewRandomReader()
	assert.Equal(t, errClosed, err)

	cert := generateRandomCert(t)

	err = ctx.ImportCertificate(bytes, cert)
	assert.Equal(t, errClosed, err)

	err = ctx.ImportCertificateWithLabel(bytes, bytes, cert)
	assert.Equal(t, errClosed, err)

	err = ctx.ImportCertificateWithAttributes(NewAttributeSet(), cert)

	assert.Equal(t, errClosed, err)

	_, err = ctx.GetAttribute(nil, CkaLabel)
	assert.Equal(t, errClosed, err)

	_, err = ctx.GetAttributes(nil, []AttributeType{CkaLabel})
	assert.Equal(t, errClosed, err)

	_, err = ctx.GetPubAttribute(nil, CkaLabel)
	assert.Equal(t, errClosed, err)

	_, err = ctx.GetPubAttributes(nil, []AttributeType{CkaLabel})
	assert.Equal(t, errClosed, err)
}
