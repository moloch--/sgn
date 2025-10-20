package sgn

import (
	"strings"
	"testing"
)

func TestGetRandomRegisterSizes(t *testing.T) {
	enc32 := &Encoder{architecture: 32}
	reg32 := enc32.GetRandomRegister(32)
	if !strings.HasPrefix(reg32, "E") {
		t.Fatalf("expected 32-bit register with E prefix, got %q", reg32)
	}

	enc64 := &Encoder{architecture: 64}
	reg64 := enc64.GetRandomRegister(64)
	if !strings.HasPrefix(reg64, "R") {
		t.Fatalf("expected 64-bit register with R prefix, got %q", reg64)
	}
}

func TestGetRandomRegisterInvalidSizePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid register size")
		}
	}()
	encoder := &Encoder{architecture: 32}
	encoder.GetRandomRegister(48)
}

func TestStackAndBasePointer(t *testing.T) {
	enc32 := &Encoder{architecture: 32}
	if ptr := enc32.GetStackPointer(); ptr != "ESP" {
		t.Fatalf("expected ESP for 32-bit stack pointer, got %s", ptr)
	}
	if bp := enc32.GetBasePointer(); bp != "EBP" {
		t.Fatalf("expected EBP for 32-bit base pointer, got %s", bp)
	}

	enc64 := &Encoder{architecture: 64}
	if ptr := enc64.GetStackPointer(); ptr != "RSP" {
		t.Fatalf("expected RSP for 64-bit stack pointer, got %s", ptr)
	}
	if bp := enc64.GetBasePointer(); bp != "RBP" {
		t.Fatalf("expected RBP for 64-bit base pointer, got %s", bp)
	}
}

func TestGetSafeRandomRegisterExcludes(t *testing.T) {
	enc := &Encoder{architecture: 32}
	reg, err := enc.GetSafeRandomRegister(32, "EAX")
	if err != nil {
		t.Fatalf("unexpected error selecting safe register: %v", err)
	}
	if reg == "EAX" {
		t.Fatal("expected safe register selection to exclude EAX")
	}
}

func TestGetSafeRandomRegisterInvalidSize(t *testing.T) {
	enc := &Encoder{architecture: 64}
	if _, err := enc.GetSafeRandomRegister(40, "RAX"); err == nil {
		t.Fatal("expected error for unsupported register size")
	}
}

func TestAssemblerHelpers(t *testing.T) {
	encoder := &Encoder{architecture: 32}
	requireAssembler(t, encoder)
	code := "NOP;NOP;"

	bin, ok := encoder.Assemble(code)
	if !ok {
		t.Fatalf("expected assembler success for %q", code)
	}
	if len(bin) != 2 {
		t.Fatalf("expected assembled length 2, got %d", len(bin))
	}

	if size := encoder.GetAssemblySize(code); size != 2 {
		t.Fatalf("expected assembly size 2, got %d", size)
	}
}

func TestGenerateIPToStack(t *testing.T) {
	encoder := &Encoder{architecture: 32}
	requireAssembler(t, encoder)
	ip := encoder.GenerateIPToStack()
	if len(ip) != 5 {
		t.Fatalf("expected CALL to be 5 bytes, got %d", len(ip))
	}
}

func TestAddCallOverLength(t *testing.T) {
	encoder := &Encoder{architecture: 32}
	requireAssembler(t, encoder)
	payload := []byte{0x90, 0x90, 0x90}

	out, err := encoder.AddCallOver(payload)
	if err != nil {
		t.Fatalf("unexpected error adding call-over: %v", err)
	}
	if len(out) != len(payload)+5 {
		t.Fatalf("expected payload length %d, got %d", len(payload)+5, len(out))
	}
}

func TestAddJumpsOverLength(t *testing.T) {
	encoder := &Encoder{architecture: 32}
	requireAssembler(t, encoder)
	payload := []byte{0x90, 0x90}

	jmp, err := encoder.AddJmpOver(payload)
	if err != nil {
		t.Fatalf("unexpected error adding jmp-over: %v", err)
	}
	if len(jmp) != len(payload)+2 {
		t.Fatalf("expected short jump length %d, got %d", len(payload)+2, len(jmp))
	}

	cond, err := encoder.AddCondJmpOver(payload)
	if err != nil {
		t.Fatalf("unexpected error adding conditional jump: %v", err)
	}
	if len(cond) < len(payload)+2 {
		t.Fatalf("expected conditional jump to extend payload by at least 2 bytes, got %d", len(cond))
	}
}

func TestGetRandomStackAddressFormat(t *testing.T) {
	encoder := &Encoder{architecture: 32}

	addr := encoder.GetRandomStackAddress()
	if !strings.HasPrefix(addr, "[") || !strings.HasSuffix(addr, "]") {
		t.Fatalf("expected stack address in bracket form, got %q", addr)
	}
	if !strings.Contains(addr, "SP") {
		t.Fatalf("expected stack address to reference stack pointer, got %q", addr)
	}
}
