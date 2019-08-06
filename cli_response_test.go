package ssp

import "testing"

func TestAskButtonParse(t *testing.T) {
	b, u := splitButton("button;https://example.com")
	if b != "button" {
		t.Errorf("didn't get button value: %v", b)
	}
	if u != "https://example.com" {
		t.Errorf("Failed url: %v", u)
	}
}

func TestAskButtonNoURL(t *testing.T) {
	b, u := splitButton("button")
	if b != "button" {
		t.Errorf("didn't get button value: %v", b)
	}
	if u != "" {
		t.Errorf("Failed url: %v", u)
	}
}

func TestAskButtonNoURLWithSemi(t *testing.T) {
	b, u := splitButton("button;")
	if b != "button" {
		t.Errorf("didn't get button value: %v", b)
	}
	if u != "" {
		t.Errorf("Failed url: %v", u)
	}
}

func TestAskNoButtonWithURL(t *testing.T) {
	b, u := splitButton(";https://example.com")
	if b != "" {
		t.Errorf("didn't get button value: %v", b)
	}
	if u != "https://example.com" {
		t.Errorf("Failed url: %v", u)
	}
}
