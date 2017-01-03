package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestMakePrivKey(t *testing.T) {
	testCases := []struct {
		rand, privHex string
	}{
		{
			"00000000000000000000000000000000",
			"3030303030303030303030303030303030303030303030303030303030303070",
		},
		{
			strings.Repeat("\x00", 32),
			"0000000000000000000000000000000000000000000000000000000000000040",
		},
		{
			strings.Repeat("\xFF", 32),
			"f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		},
	}
	for _, c := range testCases {
		rand := bytes.NewBufferString(c.rand)
		var priv [ecdhLen]byte
		if err := makePrivKey(rand, &priv); err != nil {
			t.Errorf("makePrivKey: %s", err)
		} else if h := hex.EncodeToString(priv[:]); h != c.privHex {
			t.Errorf("makePrivKey: priv want %s, got %s", c.privHex, h)
		}
	}
}

func TestMakePrivKeyError(t *testing.T) {
	testCases := []struct {
		rand, err string
	}{
		{
			"0000000000000000000000000000000",
			"unexpected EOF",
		},
	}
	for _, c := range testCases {
		rand := bytes.NewBufferString(c.rand)
		var priv [ecdhLen]byte
		if err := makePrivKey(rand, &priv); err == nil {
			t.Errorf("makePrivKey: want error %s, got none", c.err)
		} else if e := err.Error(); !strings.Contains(e, c.err) {
			t.Errorf("makePrivKey: want error %s, got %s", c.err, e)
		}
	}
}

func TestMakePubKey(t *testing.T) {
	testCases := []struct {
		privHex, pubHex string
	}{
		{
			"0000000000000000000000000000000000000000000000000000000000000040",
			"2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
		},
		{
			"3030303030303030303030303030303030303030303030303030303030303070",
			"e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f",
		},
	}
	for _, c := range testCases {
		var priv, pub [ecdhLen]byte
		priv1, err := hex.DecodeString(c.privHex)
		if err != nil {
			panic("bad hex in priv key")
		}
		copy(priv[:], priv1)
		makePubKey(&pub, &priv)
		pubHex := hex.EncodeToString(pub[:])
		if pubHex != c.pubHex {
			t.Errorf("makePubKey: got %s, want %s", pubHex, c.pubHex)
		}
	}
}

func TestMakeSharedSecret(t *testing.T) {
	testCases := []struct {
		selfPrivHex, peerPubHex, sharedHex string
	}{
		{
			"0000000000000000000000000000000000000000000000000000000000000040",
			"e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f",
			"c6a9d8429e027b1ff1fa7fc3c0e481fc48e566d907080a2ed03fa3418a04f564",
		},
		{
			"3030303030303030303030303030303030303030303030303030303030303070",
			"2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
			"c6a9d8429e027b1ff1fa7fc3c0e481fc48e566d907080a2ed03fa3418a04f564",
		},
	}
	for _, c := range testCases {
		var selfPriv, peerPub, shared [ecdhLen]byte
		selfPriv1, err := hex.DecodeString(c.selfPrivHex)
		if err != nil {
			panic("bad hex in self priv key")
		}
		copy(selfPriv[:], selfPriv1)
		peerPub1, err := hex.DecodeString(c.peerPubHex)
		if err != nil {
			panic("bad hex in peer pub key")
		}
		copy(peerPub[:], peerPub1)
		makeSharedSecret(&shared, &selfPriv, &peerPub)
		sharedHex := hex.EncodeToString(shared[:])
		if sharedHex != c.sharedHex {
			t.Errorf("makeSharedSecret: got %s, want %s", sharedHex, c.sharedHex)
		}
	}
}

func TestWriteNonce(t *testing.T) {
	testCases := []struct {
		i        uint64
		nonceHex string
	}{
		{
			0,
			"0000000000000000",
		},
		{
			1,
			"0100000000000000",
		},
		{
			9999999999999,
			"ff9f724e18090000",
		},
	}
	for _, c := range testCases {
		nonce := make([]byte, 8)
		writeNonce(nonce, c.i)
		nonceHex := hex.EncodeToString(nonce)
		if nonceHex != c.nonceHex {
			t.Errorf("writeNonce(%d): got %s, want %s", c.i, nonceHex, c.nonceHex)
		}
	}
}

func TestMakeAEAD(t *testing.T) {
	testCases := []struct {
		secret, label, pt, ctHex string
	}{
		{
			secret: "",
			label:  "",
			pt:     "",
			ctHex:  "55c352d0c74948a56c504f0e549ef460",
		},
		{
			secret: "good long password",
			label:  "some label",
			pt:     "some plaintext",
			ctHex:  "0b87a7dc1d90992469583d9222efa7eff21b33f4da7d1ae5cf355eb3ff81",
		},
	}
	for _, c := range testCases {
		aead, err := makeAEAD(c.secret, c.label)
		if err != nil {
			t.Errorf("makeAEAD: got error %s", err)
			continue
		}
		nonce := make([]byte, aead.NonceSize())
		ct := aead.Seal(nil, nonce, []byte(c.pt), nil)
		ctHex := hex.EncodeToString(ct)
		if ctHex != c.ctHex {
			t.Errorf(
				"makeAEAD(%q, %q), pt=%q: got %s, want %s",
				c.secret, c.label, c.pt, ctHex, c.ctHex,
			)
			continue
		}
		pt2, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Errorf("makeAEAD, aead.Open: got error %s", err)
			continue
		}
		if string(pt2) != c.pt {
			t.Errorf(
				"makeAEAD(%q, %q), pt=%q is %q after decryption",
				c.secret, c.label, c.pt, string(pt2),
			)
			continue
		}
	}
}
