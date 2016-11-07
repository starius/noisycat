package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ecdhLen = 32
	aesLen  = 16
)

func makePrivKey(rand io.Reader, priv *[ecdhLen]byte) error {
	// See http://cr.yp.to/ecdh.html
	_, err := io.ReadFull(rand, priv[:])
	if err != nil {
		return err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	return nil
}

func makePubKey(pub, priv *[ecdhLen]byte) {
	curve25519.ScalarBaseMult(pub, priv)
}

func makeSharedSecret(dst, selfPriv, peerPub *[ecdhLen]byte) {
	curve25519.ScalarMult(dst, selfPriv, peerPub)
}

func writeNonce(nonce []byte, i uint64) {
	binary.LittleEndian.PutUint64(nonce, i)
}

func makeAEAD(secret, label string) (cipher.AEAD, error) {
	r := hkdf.New(
		sha256.New,
		[]byte(secret),
		nil,
		[]byte(label),
	)
	aesKey := make([]byte, aesLen)
	_, err := io.ReadFull(r, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %s", err)
	}
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make AES cipher: %s", err)
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to make GCM AE: %s", err)
	}
	return aead, nil
}
