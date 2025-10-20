package sgn

import "testing"

func requireAssembler(t *testing.T, encoder *Encoder) {
	t.Helper()
	if _, ok := encoder.Assemble("NOP"); !ok {
		t.Skip("keystone assembler unavailable; skipping assembler-dependent test")
	}
}
