package sgn

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func TestRandomLabelFormat(t *testing.T) {
	rand.New(rand.NewSource(10))
	label := RandomLabel()
	if len(label) != 5 {
		t.Fatalf("expected random label length 5, got %d", len(label))
	}
	for _, r := range label {
		if !unicode.IsLetter(r) {
			t.Fatalf("expected label to contain only letters, got %q", label)
		}
	}
}

func TestGetRandomOperandValueFormats(t *testing.T) {
	rand.New(rand.NewSource(11))
	encoder := &Encoder{architecture: 64}

	if val := encoder.GetRandomOperandValue("imm8"); !strings.HasPrefix(val, "0x") {
		t.Fatalf("expected imm8 operand to be hex literal, got %q", val)
	}
	if val := encoder.GetRandomOperandValue("imm16"); !strings.HasPrefix(val, "0x") {
		t.Fatalf("expected imm16 operand to be hex literal, got %q", val)
	}
	if val := encoder.GetRandomOperandValue("imm32"); !strings.HasPrefix(val, "0x") {
		t.Fatalf("expected imm32 operand to be hex literal, got %q", val)
	}
	if val := encoder.GetRandomOperandValue("imm64"); !strings.HasPrefix(val, "0x") {
		t.Fatalf("expected imm64 operand to be hex literal, got %q", val)
	}

	regVal := encoder.GetRandomOperandValue("r32")
	if !strings.HasPrefix(regVal, "R") && !strings.HasPrefix(regVal, "E") {
		t.Fatalf("expected register operand, got %q", regVal)
	}

	memVal := encoder.GetRandomOperandValue("m32")
	if !strings.Contains(memVal, "PTR") || !strings.Contains(memVal, "[") {
		t.Fatalf("expected memory operand with PTR syntax, got %q", memVal)
	}

	rand.New(rand.NewSource(12))
	tableVal := encoder.GetRandomOperandValue("r/m16")
	if len(tableVal) == 0 {
		t.Fatal("expected r/m16 operand to be non-empty")
	}
}

func TestGetRandomUnsafeAssemblyContainsRegister(t *testing.T) {
	rand.New(rand.NewSource(13))
	encoder := &Encoder{architecture: 64}
	dest := "RAX"

	asm := encoder.GetRandomUnsafeAssembly(dest)
	if !strings.HasSuffix(asm, ";") {
		t.Fatalf("expected unsafe assembly to end with semicolon, got %q", asm)
	}
	hasRegisterVariant := false
	for _, variant := range []string{"RAX", "EAX", "AX", "AL"} {
		if strings.Contains(asm, variant) {
			hasRegisterVariant = true
			break
		}
	}
	if !hasRegisterVariant {
		t.Fatalf("expected assembly to reference register variants of %s, got %q", dest, asm)
	}
	parts := strings.Split(asm, ",")
	if len(parts) != 2 {
		t.Fatalf("expected assembly to contain one operand separator, got %q", asm)
	}
	second := strings.TrimSpace(strings.TrimSuffix(parts[1], ";"))
	if strings.Contains(second, "[") {
		return
	}
	if strings.HasPrefix(second, "0x") {
		if _, err := strconv.ParseInt(second, 0, 64); err != nil {
			t.Fatalf("expected numeric immediate operand, got %q", second)
		}
		return
	}
	upper := strings.ToUpper(second)
	if include(SupportedOperandTypes, upper) {
		return
	}
	t.Fatalf("expected second operand to be numeric, memory, or register, got %q", second)
}

func TestIncludeHelper(t *testing.T) {
	arr := []string{"A", "B", "C"}
	if !include(arr, "B") {
		t.Fatal("expected include helper to find existing element")
	}
	if include(arr, "Z") {
		t.Fatal("expected include helper to report missing element")
	}
}
