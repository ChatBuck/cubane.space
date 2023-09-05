package crypto

import (
	//"crypto/rand"
	//"encoding/hex"
	"fmt"
	//"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()),privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T){
	// seed := make([]byte, 32)
	// io.ReadFull(rand.Reader, seed)
	// fmt.Println(hex.EncodeToString(seed))

	var (
		seed = "ea360aafd45e86557c85264d07cfdad7098b94079b6eb7246902e896130a4dc0"
		privKey = NewPrivateKeyFromString(seed)
		addressStr = "9e3db64fdce657055f5ab6c31226649c83a4f5e1"
	)

	assert.Equal(t, privKeyLen,len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t,addressStr,address.String())
	//fmt.Println(address)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")


	sig := privKey.Sign(msg)
	assert.True(t,sig.Verify(pubKey,msg ))

	// Test with invalid msg
	assert.False(t,sig.Verify(pubKey,[]byte("foo") ))

	// Test with invalid pubKey
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey,msg))
}

func TestPublicKeyToAddress(t *testing.T){
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()

	assert.Equal(t, addressLen,len(address.Bytes()))
	fmt.Println(address)
}