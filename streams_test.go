package main

import (
	"encoding/hex"
	"testing"
)

func TestPack(t *testing.T) {
	testCases := []struct {
		state   int32
		dataLen int
		ptLen   int
		ptHex   string
	}{
		{
			state:   0,
			dataLen: 10,
			ptLen:   20,
			ptHex:   "000a000000000000000000000000000000000000",
		},
		{
			state:   1,
			dataLen: 10,
			ptLen:   20,
			ptHex:   "010a000000000000000000000000000000000000",
		},
		{
			state:   1,
			dataLen: 1,
			ptLen:   20,
			ptHex:   "0101000000000000000000000000000000000000",
		},
	}
	for _, c := range testCases {
		pt := make([]byte, c.ptLen)
		pack(pt, c.state, c.dataLen)
		if ptHex := hex.EncodeToString(pt); ptHex != c.ptHex {
			t.Errorf(
				"pack(%#v, %#v): pt want %s, got %s",
				c.state, c.dataLen, c.ptHex, ptHex,
			)
		}
	}
}

func TestUnpack(t *testing.T) {
	testCases := []struct {
		ptHex   string
		state   int32
		dataHex string
	}{
		{
			ptHex:   "0001000000000000000000000000000000000000",
			state:   0,
			dataHex: "00",
		},
		{
			ptHex:   "0101000000000000000000000000000000000000",
			state:   1,
			dataHex: "00",
		},
		{
			ptHex:   "0002001234500000000000000000000000000000",
			state:   0,
			dataHex: "1234",
		},
	}
	for _, c := range testCases {
		pt, err := hex.DecodeString(c.ptHex)
		if err != nil {
			panic("failed to decode pt hex")
		}
		state, data := unpack(pt)
		if state != c.state {
			t.Errorf(
				"unpack(%s): want state %d, got %d",
				c.ptHex, c.state, state,
			)
		}
		if dataHex := hex.EncodeToString(data); dataHex != c.dataHex {
			t.Errorf(
				"unpack(%s): want data %s, got %s",
				c.ptHex, c.dataHex, dataHex,
			)
		}
	}
}
