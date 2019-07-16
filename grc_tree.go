package ssp

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/blowfish"
)

// GrcTree Creates a 64-bit nut based on the GRC spec using a monotonic counter
// and blowfish cipher
type GrcTree struct {
	monotonicCounter uint64
	cipher           *blowfish.Cipher
	key              []byte
}

// NewGrcTree takes an initial counter value (in the case of reboot) and
// a blowfish key (use a max key of random 56 bytes)
// https://godoc.org/golang.org/x/crypto/blowfish
func NewGrcTree(counterInit uint64, blowfishKey []byte) (*GrcTree, error) {
	cipher, err := blowfish.NewCipher(blowfishKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize blowfish cipher: %v", err)
	}
	return &GrcTree{
		monotonicCounter: counterInit,
		cipher:           cipher,
		key:              blowfishKey,
	}, nil
}

// Nut Create a nut based on the GRC spec.
// payload is ignored as the counter is managed internally
func (gt *GrcTree) Nut(payload interface{}) (Nut, error) {
	nextValue := atomic.AddUint64(&gt.monotonicCounter, 1)
	nextValueBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nextValueBytes, nextValue)
	encrypted := make([]byte, 8)
	gt.cipher.Encrypt(encrypted, nextValueBytes)
	return Nut(Sqrl64.EncodeToString(encrypted)), nil
}
