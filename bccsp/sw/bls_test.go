package sw

import (
	"encoding/asn1"
	"github.com/Nik-U/pbc"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bls"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBLSSignerSign(t *testing.T)  {
	t.Parallel()

	signer := &blsSigner{}
	verifierPrivateKey := &blsPrivateKeyVerifier{}
	verifierPublicKey := &blsPublicKeyVerifier{}

	// Generate a key
	kg := blsKeyGenerator{160,521}
	k, err := kg.KeyGen(&bccsp.BLSKeyGenOpts{true})
	assert.NoError(t, err)
	kb,_:=k.Bytes()
	var kr= new(bls.PrivateKeyASN1)
	 asn1.Unmarshal(kb,kr)
	param,_:=pbc.NewParamsFromString(kr.Params)
	pairing:=pbc.NewPairing(param)
	kn:=&blsPrivateKey{&bls.PrivateKey{
		X:pairing.NewZr().SetBytes(kr.X),
		PubKey:&bls.PublicKey{Gx:pairing.NewG2().SetBytes(kr.Gx)},
		G:pairing.NewG2().SetBytes(kr.G),
		Params: kr.Params,
	}}

	assert.NotNil(t,kn)
	pk, err := k.PublicKey()
	assert.NoError(t, err)
	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	sigma2, err := signer.Sign(kn, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma2)

	assert.EqualValues(t,sigma,sigma2)
	// Verify


	valid, err := verifierPrivateKey.Verify(k, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma2, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma2, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}