package utils

import "testing"

func TestContainsBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	if !containsBytes(data, []byte{0x02}) {
		t.Fatal("expected containsBytes to detect matching byte")
	}
	if containsBytes(data, []byte{0xFF}) {
		t.Fatal("expected containsBytes to return false for missing byte")
	}
}

func TestIsASCIIPrintable(t *testing.T) {
	if !IsASCIIPrintable("SGN Encoder") {
		t.Fatal("expected plain ASCII string to be printable")
	}
	if IsASCIIPrintable("bad\nstring") {
		t.Fatal("expected newline to make string non-printable")
	}
	if IsASCIIPrintable("雪") {
		t.Fatal("expected non-ASCII rune to fail printable check")
	}
}
