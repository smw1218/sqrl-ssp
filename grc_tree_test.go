package ssp

import "testing"

func TestGrcStaticGenerate(t *testing.T) {
	tree, err := NewGrcTree(10, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	nut, err := tree.Nut()
	if err != nil {
		t.Fatalf("Error creating nut: %v", err)
	}

	if len(nut) != 11 {
		t.Fatalf("Nut length is: %d expected: 11", len(nut))
	}

	if nut != "xi6Qzk1Kmrg" {
		t.Fatalf("Expected nut value %v but got %v", "xi6Qzk1Kmrg", nut)
	}
}

func TestGrcUniqueGenerate(t *testing.T) {
	tree, err := NewGrcTree(9, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("Error creating tree: %v", err)
	}

	values := make(map[Nut]struct{}, 10)

	for i := 0; i < 10; i++ {
		nut, err := tree.Nut()
		if err != nil {
			t.Fatalf("Error creating nut: %v", err)
		}
		if _, ok := values[nut]; ok {
			t.Fatalf("Found duplicate %v", nut)
		}
		values[nut] = struct{}{}
	}

	if _, ok := values["xi6Qzk1Kmrg"]; !ok {
		t.Fatalf("didn't find expected value for 10: xi6Qzk1Kmrg in genereated nuts")
	}
}
