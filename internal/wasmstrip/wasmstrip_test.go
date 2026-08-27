package wasmstrip

import (
	"bytes"
	"testing"
)

func TestStripCustomSections(t *testing.T) {
	largeCustomPayload := bytes.Repeat([]byte{0x7f}, 130)
	module := append([]byte{}, wasmHeader...)
	module = append(module, section(0, []byte{0x01, 'a'})...)
	module = append(module, section(1, []byte{0x00})...)
	module = append(module, section(0, largeCustomPayload)...)
	module = append(module, section(10, []byte{0x00})...)
	module = append(module, section(0, []byte{0x01, 'z'})...)

	want := append([]byte{}, wasmHeader...)
	want = append(want, section(1, []byte{0x00})...)
	want = append(want, section(10, []byte{0x00})...)

	got, err := StripCustomSections(module)
	if err != nil {
		t.Fatalf("StripCustomSections() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("StripCustomSections() = %x, want %x", got, want)
	}
}

func TestStripCustomSectionsPreservesSectionEncoding(t *testing.T) {
	// The size uses a bounded but non-minimal LEB encoding. The normalizer must
	// preserve standard section bytes rather than re-encoding them.
	nonCanonicalTypeSection := []byte{0x01, 0x81, 0x00, 0x00}
	module := append([]byte{}, wasmHeader...)
	module = append(module, nonCanonicalTypeSection...)
	module = append(module, section(0, []byte{0x01, 'x'})...)

	want := append(append([]byte{}, wasmHeader...), nonCanonicalTypeSection...)
	got, err := StripCustomSections(module)
	if err != nil {
		t.Fatalf("StripCustomSections() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("StripCustomSections() = %x, want %x", got, want)
	}
}

func TestStripCustomSectionsRejectsMalformedModules(t *testing.T) {
	tests := map[string][]byte{
		"missing header": nil,
		"wrong version":  {0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00},
		"missing size":   append(append([]byte{}, wasmHeader...), 0x01),
		"truncated body": append(append([]byte{}, wasmHeader...), 0x01, 0x02, 0x00),
		"size overflow": append(append([]byte{}, wasmHeader...),
			0x01, 0x80, 0x80, 0x80, 0x80, 0x10),
		"size too long": append(append([]byte{}, wasmHeader...),
			0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00),
	}

	for name, module := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := StripCustomSections(module); err == nil {
				t.Fatal("StripCustomSections() error = nil, want malformed module error")
			}
		})
	}
}

func section(id byte, payload []byte) []byte {
	encoded := []byte{id}
	encoded = append(encoded, encodeULEB32(uint32(len(payload)))...)
	return append(encoded, payload...)
}

func encodeULEB32(value uint32) []byte {
	var encoded []byte
	for {
		current := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			current |= 0x80
		}
		encoded = append(encoded, current)
		if value == 0 {
			return encoded
		}
	}
}
