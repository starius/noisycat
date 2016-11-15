package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sizeLen       = 2
	stateLen      = 1
	ptWriteQueue  = 10
	ptStopWriteAt = 5
)

// TODO use ranged for to read from chan

func pack(pt []byte, state int32, dataLen int) {
	pt[0] = byte(state)
	binary.LittleEndian.PutUint16(pt[stateLen:], uint16(dataLen))
}

func unpack(pt []byte) (state int32, data []byte) {
	state = int32(pt[0])
	dataLen := binary.LittleEndian.Uint16(
		pt[stateLen : stateLen+sizeLen],
	)
	data = pt[stateLen+sizeLen : stateLen+sizeLen+dataLen]
	return
}

func stripHeader(pt []byte) (data []byte) {
	return pt[stateLen+sizeLen:]
}

func encrypt(
	r io.Reader, w io.Writer,
	aead cipher.AEAD,
	ctSize int, d time.Duration,
	peerState, selfState *int32,
) error {
	ptSize := ctSize - aead.Overhead()
	ptChan := make(chan []byte) // read goroutine -> main
	readErr := make(chan error) // read goroutine -> main
	mainErr := make(chan bool)  // main -> read goroutine (quit signal)
	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		mainErr <- true
		wg.Wait()
	}()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for {
			select {
			case <-mainErr:
				return
			case <-ticker.C:
			}
			if atomic.LoadInt32(peerState) != 0 {
				// Peer's queue >= ptStopWriteAt.
				continue
			}
			pt := make([]byte, ptSize, ctSize)
			data := stripHeader(pt)
			// Not ReadFull not to wait if less data available.
			n, err := r.Read(data)
			if n > 0 {
				pack(pt, atomic.LoadInt32(selfState), n)
				ptChan <- pt
			}
			if err != nil {
				readErr <- err
				return
			}
		}
	}()
	nonce := make([]byte, aead.NonceSize())
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for i := 0; ; i++ {
		select {
		case err := <-readErr:
			return fmt.Errorf("failed to read plaintext: %s", err)
		case <-ticker.C:
		}
		var pt []byte
		select {
		case pt = <-ptChan:
		default:
			// Do not block.
			pt = make([]byte, ptSize)
		}
		writeNonce(nonce, uint64(i))
		ct := aead.Seal(pt[:0], nonce, pt, nil)
		if len(ct) != ctSize {
			return fmt.Errorf("#ct: got %d, want %d", len(ct), ctSize)
		}
		_, err := w.Write(ct)
		if err != nil {
			return fmt.Errorf("failed to write encrypted: %s", err)
		}
	}
	return nil // Unreachable.
}

func decrypt(
	r io.Reader, w io.Writer,
	aead cipher.AEAD,
	ctSize int, d time.Duration,
	peerState, selfState *int32,
) error {
	dataChan := make(chan []byte, ptWriteQueue)
	writeErr := make(chan error)
	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		close(dataChan)
		wg.Wait()
	}()
	go func() {
		defer wg.Done()
		for {
			data, ok := <-dataChan
			if !ok {
				return
			}
			_, err := w.Write(data)
			if err != nil {
				writeErr <- err
				return
			}
		}
	}()
	nonce := make([]byte, aead.NonceSize())
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for i := 0; ; i++ {
		select {
		case err := <-writeErr:
			return fmt.Errorf("failed to write decrypted: %s", err)
		case <-ticker.C:
		}
		ct := make([]byte, ctSize)
		_, err := io.ReadFull(r, ct)
		if err != nil {
			return fmt.Errorf("failed to read ciphertext: %s", err)
		}
		writeNonce(nonce, uint64(i))
		pt, err := aead.Open(ct[:0], nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt or verify: %s", err)
		}
		state, data := unpack(pt)
		atomic.StoreInt32(peerState, state)
		dataChan <- data
		if len(dataChan) == ptWriteQueue {
			return fmt.Errorf("congestion in upstream")
		} else if len(dataChan) >= ptStopWriteAt {
			atomic.StoreInt32(selfState, 1)
		} else {
			atomic.StoreInt32(selfState, 0)
		}
	}
	return nil // Unreachable.
}

func connect(
	p, c io.ReadWriteCloser,
	key []byte,
	encLabel, decLabel string,
	ctSize int, d time.Duration,
) error {
	if ctSize < ecdhLen {
		return fmt.Errorf("too small ctSize: %d < %d", ctSize, ecdhLen)
	}
	var priv, pub, peerPub, shared [ecdhLen]byte
	if err := makePrivKey(rand.Reader, &priv); err != nil {
		return fmt.Errorf("failed to generate ECDH key: %s", err)
	}
	makePubKey(&pub, &priv)
	decBuf := make([]byte, ctSize)
	encBuf := make([]byte, ctSize)
	copy(decBuf, pub[:])
	_, err := io.ReadFull(rand.Reader, decBuf[ecdhLen:])
	if err != nil {
		return fmt.Errorf("failed to fill with random: %s", err)
	}
	_, err = c.Write(decBuf)
	if err != nil {
		return fmt.Errorf("failed to send pubkey: %s", err)
	}
	_, err = io.ReadFull(c, encBuf)
	if err != nil {
		return fmt.Errorf("failed to receive pubkey: %s", err)
	}
	copy(peerPub[:], encBuf)
	makeSharedSecret(&shared, &priv, &peerPub)
	secret := string(shared[:]) + string(key)
	encAEAD, err := makeAEAD(secret, encLabel)
	if err != nil {
		return fmt.Errorf("failed to make encryption AE: %s", err)
	}
	decAEAD, err := makeAEAD(secret, decLabel)
	if err != nil {
		return fmt.Errorf("failed to make decryption AE: %s", err)
	}
	errChan := make(chan error, 2)
	var peerState, selfState int32
	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		err = encrypt(
			p, c,
			encAEAD,
			ctSize, d,
			&peerState, &selfState,
		)
		errChan <- err
		p.Close()
		c.Close()
	}()
	go func() {
		defer wg.Done()
		err = decrypt(
			c, p,
			decAEAD,
			ctSize, d,
			&peerState, &selfState,
		)
		errChan <- err
		p.Close()
		c.Close()
	}()
	return <-errChan
}
