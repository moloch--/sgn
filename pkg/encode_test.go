package sgn

import (
	"strings"
	"testing"
)

func TestNewEncoderDefaults(t *testing.T) {
	encoder, err := NewEncoder(32)
	if err != nil {
		t.Fatalf("expected encoder, got error: %v", err)
	}
	if encoder.architecture != 32 {
		t.Fatalf("expected architecture 32, got %d", encoder.architecture)
	}
	if encoder.ObfuscationLimit != 50 {
		t.Fatalf("expected default obfuscation limit 50, got %d", encoder.ObfuscationLimit)
	}
	if encoder.EncodingCount != 1 {
		t.Fatalf("expected default encoding count 1, got %d", encoder.EncodingCount)
	}
	if encoder.PlainDecoder {
		t.Fatal("expected decoder obfuscation enabled by default")
	}
}

func TestNewEncoderInvalidArchitecture(t *testing.T) {
	if _, err := NewEncoder(16); err == nil {
		t.Fatal("expected error for invalid architecture, got nil")
	}
}

func TestEncoderSetArchitecture(t *testing.T) {
	encoder, err := NewEncoder(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := encoder.SetArchitecture(64); err != nil {
		t.Fatalf("expected to set architecture 64, got error: %v", err)
	}
	if encoder.architecture != 64 {
		t.Fatalf("expected architecture 64, got %d", encoder.architecture)
	}
	if err := encoder.SetArchitecture(16); err == nil {
		t.Fatal("expected error when setting invalid architecture")
	}
}

func TestCipherADFLSample(t *testing.T) {
	input := []byte{0x00, 0x11, 0x22, 0x33}
	expected := []byte{0xC0, 0xBE, 0xAF, 0x69}

	result := CipherADFL(append([]byte(nil), input...), 0x5A)
	if len(result) != len(expected) {
		t.Fatalf("expected result length %d, got %d", len(expected), len(result))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Fatalf("expected byte %d to be 0x%x, got 0x%x", i, expected[i], result[i])
		}
	}
}

func TestSchemaCipherAppliesOperations(t *testing.T) {
	encoder := &Encoder{architecture: 32}
	data := []byte{0x10, 0x20, 0x30, 0x40, 0x01, 0x02, 0x03, 0x04}
	schema := SCHEMA{
		{OP: "XOR", Key: []byte{0x01, 0x00, 0x00, 0x00}},
		{OP: "NOT"},
	}

	got := encoder.SchemaCipher(append([]byte(nil), data...), 0, schema)
	expected := []byte{0x10, 0x20, 0x30, 0x41, 0xFE, 0xFD, 0xFC, 0xFB}

	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("schema cipher mismatch at index %d: expected 0x%x, got 0x%x", i, expected[i], got[i])
		}
	}
}

func TestNewCipherSchemaProperties(t *testing.T) {
	encoder := &Encoder{architecture: 32}
	schema := encoder.NewCipherSchema(12)

	if len(schema) != 12 {
		t.Fatalf("expected schema length 12, got %d", len(schema))
	}

	validOperands := map[string]struct{}{}
	for _, op := range OPERANDS {
		validOperands[op] = struct{}{}
	}

	for i, step := range schema {
		if _, ok := validOperands[step.OP]; !ok {
			t.Fatalf("schema[%d] uses unsupported operand %q", i, step.OP)
		}
		switch step.OP {
		case "NOT":
			if step.Key != nil {
				t.Fatalf("schema[%d] NOT operand should not carry a key", i)
			}
		case "ROL", "ROR":
			if len(step.Key) != 4 {
				t.Fatalf("schema[%d] %s operand should carry 4-byte key", i, step.OP)
			}
			if step.Key[0] != 0 || step.Key[1] != 0 || step.Key[2] != 0 {
				t.Fatalf("schema[%d] %s operand must zero upper bytes, got %v", i, step.OP, step.Key)
			}
		default:
			if len(step.Key) != 4 {
				t.Fatalf("schema[%d] %s operand should carry 4-byte key, got %d", i, step.OP, len(step.Key))
			}
		}
	}
}

func TestGetSchemaTable(t *testing.T) {
	schema := SCHEMA{
		{OP: "XOR", Key: []byte{0x00, 0x00, 0x00, 0x01}},
		{OP: "NOT"},
	}

	table := GetSchemaTable(schema)
	if !strings.Contains(table, "OPERAND") {
		t.Fatal("schema table missing OPERAND header")
	}
	if !strings.Contains(table, "XOR") {
		t.Fatal("schema table missing XOR entry")
	}
	if !strings.Contains(table, "NOT") {
		t.Fatal("schema table missing NOT entry")
	}
}
