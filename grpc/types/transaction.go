package types

import (
	"crypto/sha256"

	"github.com/ashpreetsinghanand/crypto"
	"github.com/ashpreetsinghanand/proto"
	pb "github.com/golang/protobuf/proto"
)

func SignTransaction(pk *crypto.PrivateKey, tx *proto.Transaction) *crypto.Signature {
	return pk.Sign(HashTransaction(tx))
}

func HashTransaction(tx *proto.Transaction) [] byte {
	b, err := pb.Marshal(tx)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256((b))
	return hash[:]
}

func VerifyTransaction(tx *proto.Transaction) bool{
	for _,input := range tx.Inputs {
		var (
			sig = crypto.SignatureFromBytes(input.Signature)
			pubKey = crypto.PublicKeyFromBytes(input.PublicKey)
		)

		// TODO: make sure we don't run into problems after verification
		// cause we have set the signature to nil.
		input.Signature =nil
		if !sig.Verify(pubKey, HashTransaction(tx)) {
			return false
		}
	}
	return true
}