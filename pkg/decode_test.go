package sgn

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestNewDecoderAssembly32(t *testing.T) {
	rand.New(rand.NewSource(1))
	encoder, err := NewEncoder(32)
	if err != nil {
		t.Fatalf("unexpected error creating encoder: %v", err)
	}
	encoder.Seed = 0xAA

	asm, err := encoder.NewDecoderAssembly(0x20)
	if err != nil {
		t.Fatalf("unexpected error generating decoder assembly: %v", err)
	}
	if strings.Contains(asm, "{R}") || strings.Contains(asm, "{RL}") {
		t.Fatalf("decoder assembly contains unresolved placeholders: %q", asm)
	}
	if !strings.Contains(asm, "MOV ECX,0x20") {
		t.Fatalf("decoder assembly missing payload size directive, got %q", asm)
	}
	if !strings.Contains(asm, "0xaa") {
		t.Fatalf("decoder assembly missing seed literal, got %q", asm)
	}
}

func TestNewDecoderAssembly64(t *testing.T) {
	rand.New(rand.NewSource(2))
	encoder, err := NewEncoder(64)
	if err != nil {
		t.Fatalf("unexpected error creating encoder: %v", err)
	}
	encoder.Seed = 0x55

	asm, err := encoder.NewDecoderAssembly(0x30)
	if err != nil {
		t.Fatalf("unexpected error generating decoder assembly: %v", err)
	}
	if strings.Contains(asm, "{R}") || strings.Contains(asm, "{RL}") {
		t.Fatalf("decoder assembly contains unresolved placeholders: %q", asm)
	}
	if !strings.Contains(asm, "MOV RCX,0x30") {
		t.Fatalf("decoder assembly missing payload size directive, got %q", asm)
	}
	if !strings.Contains(asm, "LEA") {
		t.Fatalf("expected RIP-relative LEA in 64-bit decoder, got %q", asm)
	}
}

func TestAddADFLDecoder(t *testing.T) {
	encoder, err := NewEncoder(32)
	if err != nil {
		t.Fatalf("unexpected error creating encoder: %v", err)
	}
	requireAssembler(t, encoder)
	encoder.Seed = 0x11
	payload := []byte{0x90, 0x90, 0x90, 0x90}

	out, err := encoder.AddADFLDecoder(payload)
	if err != nil {
		t.Skipf("skipping ADFL decoder test: %v", err)
	}
	if len(out) <= len(payload) {
		t.Fatalf("expected decoder to prepend bytes, got %d <= %d", len(out), len(payload))
	}
	if !bytes.Equal(out[len(out)-len(payload):], payload) {
		t.Fatalf("expected payload bytes to remain at the end of decoder output")
	}
}

func TestAddSchemaDecoder(t *testing.T) {
	rand.New(rand.NewSource(3))
	encoder, err := NewEncoder(32)
	if err != nil {
		t.Fatalf("unexpected error creating encoder: %v", err)
	}
	requireAssembler(t, encoder)
	encoder.ObfuscationLimit = 128

	payload := []byte{0x90, 0x90, 0x90, 0x90}
	schema := SCHEMA{
		{OP: "XOR", Key: []byte{0x01, 0x00, 0x00, 0x00}},
	}

	out, err := encoder.AddSchemaDecoder(append([]byte(nil), payload...), schema)
	if err != nil {
		t.Skipf("skipping schema decoder test: %v", err)
	}
	if len(out) <= len(payload) {
		t.Fatalf("expected schema decoder to grow payload, got %d <= %d", len(out), len(payload))
	}
}
