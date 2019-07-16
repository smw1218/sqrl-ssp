package ssp

import "testing"

func TestRandomGenerate(t *testing.T) {
	numBytes := 16
	tree, err := NewRandomTree(numBytes)
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	nut, err := tree.Nut(nil)
	if err != nil {
		t.Fatalf("Error creating nut: %v", err)
	}
	if checkByteSize(nut) != numBytes {
		t.Fatalf("Wrong size expected %d but got %d", numBytes, checkByteSize(nut))
	}
}
func TestRandomUniqueGenerate(t *testing.T) {
	numBytes := 8
	tree, err := NewRandomTree(numBytes)
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	values := make(map[Nut]struct{}, 10)

	for i := 0; i < 10; i++ {
		nut, err := tree.Nut(nil)
		if err != nil {
			t.Fatalf("Error creating nut: %v", err)
		}
		if checkByteSize(nut) != numBytes {
			t.Fatalf("Wrong size expected %d but got %d", numBytes, checkByteSize(nut))
		}
		if _, ok := values[nut]; ok {
			t.Fatalf("Found duplicate %v", nut)
		}
		values[nut] = struct{}{}
	}
}

func checkByteSize(nut Nut) int {
	bytes, _ := Sqrl64.DecodeString(string(nut))
	return len(bytes)
}
