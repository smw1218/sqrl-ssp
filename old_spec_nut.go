package ssp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"time"
)

var globalCounter uint32

// Implementing nut suggestion from (old spec):
// https://www.grc.com/sqrl/server.htm
type OldSpecTree struct {
	key      []byte
	aesBlock cipher.Block
	// allow override for testing
	noiseSource func() (uint32, error)
	timeSource  func() uint32
}

func NewTree(key []byte) (*OldSpecTree, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("Key is %v bytes and must be exactly 16", len(key))
	}
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize AES cipher: %v", err)
	}
	return &OldSpecTree{
		key:         key,
		aesBlock:    aesBlock,
		noiseSource: cryptoNoiseSource,
		timeSource:  realTimeSource,
	}, nil
}

// Implementing nut suggestion from:
// https://www.grc.com/sqrl/server.htm
type NutParts struct {
	IPAddress uint32
	TimeUnix  uint32
	Counter   uint32
	Noise     uint32
	Source    bool // true if QR Code
}

func cryptoNoiseSource() (uint32, error) {
	noise := make([]byte, 4)
	_, err := rand.Read(noise)
	if err != nil {
		return 0, err
	}
	// clear the MSB to return a 31 bit value
	return (uint32(noise[3])<<24 + uint32(noise[2])<<16 + uint32(noise[1])<<8 + uint32(noise[0])) & 0x7FFFFFFF, nil
}

func testNoiseSource() (uint32, error) {
	return 0, nil
}

func realTimeSource() uint32 {
	return uint32(time.Now().Unix())
}

func testTimeSource() uint32 {
	return 0
}

func (t *OldSpecTree) NewNutParts(remoteAddr string, source bool) (*NutParts, error) {
	noise, err := t.noiseSource()
	if err != nil {
		return nil, fmt.Errorf("can't read random bytes for nut")
	}
	return &NutParts{
		IPAddress: 0, // TODO
		TimeUnix:  t.timeSource(),
		Counter:   atomic.AddUint32(&globalCounter, 1),
		Noise:     noise,
		Source:    source,
	}, nil
}

func (t *OldSpecTree) Nut(payload interface{}) (Nut, error) {
	np, ok := payload.(*NutParts)
	if !ok {
		return "", fmt.Errorf("payload for OldSpecTree must be a *NutParts")
	}
	nutBytes := make([]byte, 16)
	nutBytes[0] = byte(np.IPAddress)
	nutBytes[1] = byte(np.IPAddress >> 8)
	nutBytes[2] = byte(np.IPAddress >> 16)
	nutBytes[3] = byte(np.IPAddress >> 24)

	nutBytes[4] = byte(np.TimeUnix)
	nutBytes[5] = byte(np.TimeUnix >> 8)
	nutBytes[6] = byte(np.TimeUnix >> 16)
	nutBytes[7] = byte(np.TimeUnix >> 24)

	nutBytes[8] = byte(np.Counter)
	nutBytes[9] = byte(np.Counter >> 8)
	nutBytes[10] = byte(np.Counter >> 16)
	nutBytes[11] = byte(np.Counter >> 24)

	nutBytes[12] = byte(np.Noise)
	nutBytes[13] = byte(np.Noise >> 8)
	nutBytes[14] = byte(np.Noise >> 16)
	nutBytes[15] = byte(np.Noise >> 24)

	// set the MSB if source true
	if np.Source {
		nutBytes[15] |= 0x80
	}
	encrypted := make([]byte, 16)
	t.aesBlock.Encrypt(encrypted, nutBytes)
	return Nut(Sqrl64.EncodeToString(encrypted)), nil
}

func (t *OldSpecTree) NutParts(n Nut) (*NutParts, error) {
	decoded, err := Sqrl64.DecodeString(string(n))
	if err != nil {
		return nil, fmt.Errorf("can't decode nut base64: %v", err)
	}
	if len(decoded) != 16 {
		return nil, fmt.Errorf("invalid nut length %v: must decode to exactly 16 bytes", len(decoded))
	}
	decryptedByte := make([]byte, 16)
	t.aesBlock.Decrypt(decryptedByte, decoded)

	decrypted := make([]uint32, 16)
	for i, b := range decryptedByte {
		decrypted[i] = uint32(b)
	}

	source := false
	if (decrypted[15] & 0x80) != 0 {
		source = true
	}
	return &NutParts{
		IPAddress: uint32(decrypted[3]<<24 + decrypted[2]<<16 + decrypted[1]<<8 + decrypted[0]),
		TimeUnix:  uint32(decrypted[7]<<24 + decrypted[6]<<16 + decrypted[5]<<8 + decrypted[4]),
		Counter:   uint32(decrypted[11]<<24 + decrypted[10]<<16 + decrypted[9]<<8 + decrypted[8]),
		Noise:     uint32((decrypted[15]&0x7F)<<24 + decrypted[14]<<16 + decrypted[13]<<8 + decrypted[12]),
		Source:    source,
	}, nil
}
