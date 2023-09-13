package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "bb492ca372b0c3ca87cf535421f73ef2836fbe13110dab4c6d7bb562c4572220"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "302a0c8c8be2869ed0ae86b42717647b21286dcc"
	)
	assert.Equal(t, privKeyLen, len(privKey.bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	//Тест с не валидным msg
	assert.False(t, sig.Verify(pubKey, []byte("foo")))

	//Тест с не валидным pubKey
	InvalidPrivKey := GeneratePrivateKey()
	InvalidPubKey := InvalidPrivKey.Public()
	assert.False(t, sig.Verify(InvalidPubKey, msg))
}

func TestPublcKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
