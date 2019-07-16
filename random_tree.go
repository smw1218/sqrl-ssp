package ssp

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"
)

// RandomTree produces random nuts
type RandomTree struct {
	byteSize  int
	valueChan chan Nut
}

// NewRandomTree takes a bytesize between 8 and 20
// Shorter nuts are preferred; but if you think your
// deployment would require more bits to be unique you
// can create larger ones
func NewRandomTree(byteSize int) (*RandomTree, error) {
	if byteSize < 8 || byteSize > 20 {
		return nil, fmt.Errorf("Valid sizes are between 8 and 20 bytes")
	}
	rt := &RandomTree{
		byteSize:  byteSize,
		valueChan: make(chan Nut, 1000), // buffer a thousand values to smooth out load on the enrtopy source
	}
	go rt.valueReader()
	return rt, nil
}

func (rt *RandomTree) valueReader() {
	for {
		valueBytes := make([]byte, rt.byteSize)
		_, err := rand.Read(valueBytes)
		if err != nil {
			log.Printf("error reading random bytes: %v", err)
			time.Sleep(time.Millisecond * 10)
		}
		rt.valueChan <- Nut(Sqrl64.EncodeToString(valueBytes))
	}
}

// Nut Create a pure random nut
// payload is ignored
func (rt *RandomTree) Nut(payload interface{}) (Nut, error) {
	select {
	case val := <-rt.valueChan:
		return val, nil
	case <-time.After(20 * time.Millisecond):
		return "", fmt.Errorf("timeout failed waiting for random nut generation")
	}
}
