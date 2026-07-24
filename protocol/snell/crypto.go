package snell

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
)

func deriveKey(psk, salt []byte) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
}

func newAEAD(psk, salt []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey(psk, salt))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
