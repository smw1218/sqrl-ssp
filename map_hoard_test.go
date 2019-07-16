package ssp

import (
	"testing"
	"time"
)

func TestMapHoard(t *testing.T) {
	h := NewMapHoard()

	err := h.Save(Nut("nut"), "val", time.Second)
	if err != nil {
		t.Fatalf("Failed save: %v", err)
	}

	val, err := h.Get(Nut("nut"))
	if err != nil {
		t.Fatalf("Failed get: %v", err)
	}

	if val.(string) != "val" {
		t.Fatalf("Wrong value get: %v", val)
	}

	// and again
	val, err = h.Get(Nut("nut"))
	if err != nil {
		t.Fatalf("Failed get: %v", err)
	}

	if val.(string) != "val" {
		t.Fatalf("Wrong value get: %v", val)
	}
}

func TestMapHoardGetAndDelete(t *testing.T) {
	h := NewMapHoard()

	err := h.Save(Nut("nut"), "val", time.Second)
	if err != nil {
		t.Fatalf("Failed save: %v", err)
	}

	val, err := h.GetAndDelete(Nut("nut"))
	if err != nil {
		t.Fatalf("Failed get: %v", err)
	}

	if val.(string) != "val" {
		t.Fatalf("Wrong value get: %v", val)
	}

	// and again
	val, err = h.GetAndDelete(Nut("nut"))
	if err == nil {
		t.Fatalf("Succeeded when should have failed due to expiration")
	}

	if err != NotFoundError {
		t.Fatalf("Wrong error: %v", err)
	}

	if val != nil {
		t.Fatalf("Value should be nil: %v", val)
	}
}

func TestMapHoardExpired(t *testing.T) {
	h := NewMapHoard()

	err := h.Save(Nut("nut"), "val", 0)
	if err != nil {
		t.Fatalf("Failed save: %v", err)
	}
	time.Sleep(time.Microsecond)

	val, err := h.Get(Nut("nut"))
	if err == nil {
		t.Fatalf("Succeeded when should have failed due to expiration")
	}

	if err != NotFoundError {
		t.Fatalf("Wrong error: %v", err)
	}

	if val != nil {
		t.Fatalf("Value should be nil: %v", val)
	}
}
