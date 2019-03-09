package bls

import (
	"encoding/asn1"
	"fmt"
	"github.com/Nik-U/pbc"
)
type PrivateKey struct {
	X *pbc.Element
	PubKey *PublicKey
	G *pbc.Element
	Params string
}

type PublicKey struct {
	Gx *pbc.Element
	G *pbc.Element
	Params string
}
type PrivateKeyASN1 struct {
	X []byte
	Gx []byte
	G []byte
	Params string

}

type PublicKeyASN1 struct {
	Gx []byte
	G  []byte
	Params string
}

func  (priv *PrivateKey) Sign( digest []byte) (signature []byte, err error) {
	pairing := priv.X.Pairing()
	h :=pairing.NewG1().SetFromHash(digest)
	return pairing.NewG2().PowZn(h, priv.X).Bytes(),nil
}
func (priv *PrivateKey) Bytes() ([]byte,error){
	return asn1.Marshal(PrivateKeyASN1{
		X:priv.X.Bytes(),
		Gx:priv.PubKey.Gx.Bytes(),
		G:priv.G.Bytes(),
		Params:priv.Params,
	})
}
func (pubkey *PublicKey) Bytes()([]byte,error){
	return asn1.Marshal(PublicKeyASN1{
		Gx:pubkey.Gx.Bytes(),
		G:pubkey.G.Bytes(),
		Params:pubkey.Params,
	})
}
func (pub *PublicKey) Verify(signature, digest []byte) (valid bool, err error){

	pairing :=pub.Gx.Pairing()
	sig := pairing.NewG1().SetBytes(signature)
	// To verify,  checks that e(h,g^x)=e(sig,g)
	h := pairing.NewG1().SetFromHash(digest)
	temp1 := pairing.NewGT().Pair(h, pub.Gx)
	temp2 := pairing.NewGT().Pair(sig, pub.G)
	if !temp1.Equals(temp2) {
		return false,fmt.Errorf("Signature check failed")
	} else {
		return true,nil
	}
}
func GenerateKey(rbits int,qbits int)(privKey *PrivateKey,err error){

	if rbits ==0{
		return nil,fmt.Errorf("rbits can't be 0")
	}
	if qbits==0{
		return nil,fmt.Errorf("qbits can't be 0")
	}
	params := pbc.GenerateA(uint32(rbits), uint32(qbits))
	pairing := params.NewPairing()
	g := pairing.NewG2().Rand()

	x := pairing.NewZr().Rand()
	gx := pairing.NewG2().PowZn(g, x)
	pubkey := &PublicKey{gx,g,params.String()}
	return &PrivateKey{x,pubkey,g,params.String()},nil
}

func PubKeyFromBytes(asn1pubkey []byte)(pubkey *PublicKey,err error){
	var ak = new(PublicKeyASN1)
	asn1.Unmarshal(asn1pubkey,ak)
	pairing,err:=pbc.NewPairingFromString(ak.Params)
	if err!=nil {
		return nil,err
	}
	pubkey=&PublicKey{
		Gx:pairing.NewG2().SetBytes(ak.Gx),
		G:pairing.NewG2().SetBytes(ak.G),
		Params:ak.Params,
	}

	return pubkey,nil
}

func PriKeyFromBytes(asn1prikey []byte)( privkey *PrivateKey,err error){
	var ak = new(PrivateKeyASN1)
	asn1.Unmarshal(asn1prikey,ak)
	pairing,err:=pbc.NewPairingFromString(ak.Params)
	if err!=nil {
		return nil,err
	}
	privkey=&PrivateKey{
		X:pairing.NewZr().SetBytes(ak.X),
		PubKey:&PublicKey{
			Gx:pairing.NewG2().SetBytes(ak.Gx),
			G:pairing.NewG2().SetBytes(ak.G),
			Params: ak.Params,
		},
		G:pairing.NewG2().SetBytes(ak.G),
		Params: ak.Params,
	}

	return privkey,nil
}

