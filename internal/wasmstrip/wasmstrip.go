// Package wasmstrip removes non-semantic custom sections from WebAssembly
// modules while preserving all standard sections byte-for-byte.
package wasmstrip

import (
	"bytes"
	"errors"
	"fmt"
)

var wasmHeader = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

// StripCustomSections returns module without WebAssembly custom sections.
func StripCustomSections(module []byte) ([]byte, error) {
	if len(module) < len(wasmHeader) || !bytes.Equal(module[:len(wasmHeader)], wasmHeader) {
		return nil, errors.New("invalid or unsupported WebAssembly header")
	}

	normalized := make([]byte, 0, len(module))
	normalized = append(normalized, wasmHeader...)

	for offset := len(wasmHeader); offset < len(module); {
		sectionStart := offset
		sectionID := module[offset]
		offset++

		sectionSize, payloadStart, err := readULEB32(module, offset)
		if err != nil {
			return nil, fmt.Errorf("section at offset %d: %w", sectionStart, err)
		}
		if uint64(sectionSize) > uint64(len(module)-payloadStart) {
			return nil, fmt.Errorf("section at offset %d: payload exceeds module", sectionStart)
		}

		sectionEnd := payloadStart + int(sectionSize)
		if sectionID != 0 {
			normalized = append(normalized, module[sectionStart:sectionEnd]...)
		}
		offset = sectionEnd
	}

	return normalized, nil
}

func readULEB32(data []byte, offset int) (uint32, int, error) {
	var value uint32
	for index := 0; index < 5; index++ {
		if offset >= len(data) {
			return 0, 0, errors.New("truncated section size")
		}

		current := data[offset]
		offset++
		if index == 4 && current&0xf0 != 0 {
			return 0, 0, errors.New("section size overflows u32")
		}
		value |= uint32(current&0x7f) << (7 * index)

		if current&0x80 == 0 {
			return value, offset, nil
		}
	}

	return 0, 0, errors.New("section size overflows u32")
}
