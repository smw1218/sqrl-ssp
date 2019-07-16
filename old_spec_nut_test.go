package ssp

import (
	"testing"
)

func TestStaticOldSpecNutGeneration(t *testing.T) {

	key := make([]byte, 16) // zero key

	tree, err := NewTree(key)
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	// get rid of randomness
	tree.noiseSource = testNoiseSource
	tree.timeSource = testTimeSource

	np, err := tree.NewNutParts("", true)
	if err != nil {
		t.Fatalf("Failed creating nut: %v", err)
	}

	val, _ := tree.Nut(np)
	if val != "rU4k3mKf314RDhBlegJNCg" {
		t.Fatalf("Val: %v", val)
	}
}

func TestOldSpecEncodeDecode(t *testing.T) {
	key := make([]byte, 16) // zero key

	tree, err := NewTree(key)
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	np, err := tree.NewNutParts("", true)
	if err != nil {
		t.Fatalf("Failed creating nut: %v", err)
	}

	val, _ := tree.Nut(np)

	npDecoded, err := tree.NutParts(val)
	if err != nil {
		t.Fatalf("Failed decoding nut %v", err)
	}

	if *npDecoded != *np {
		t.Fatalf("Nuts not equal after decode orginal %#v != decoded %#v", np, npDecoded)
	}
}

func TestOldSpecUnique(t *testing.T) {
	key := make([]byte, 16) // zero key

	tree, err := NewTree(key)
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	generated := make(map[Nut]struct{}, 10)
	for i := 0; i < 10; i++ {
		np, err := tree.NewNutParts("", true)
		if err != nil {
			t.Fatalf("Failed creating nut: %v", err)
		}
		nut, _ := tree.Nut(np)
		if _, found := generated[nut]; found {
			t.Errorf("failed uniqueness test")
		}
		generated[nut] = struct{}{}
	}
}
