package sgn_test

import (
	"testing"

	sgn "github.com/moloch--/sgn/pkg"
)

// These assignments intentionally spell out the public Go API that existed
// before the Rust port. A receiver, parameter, result, field, or global type
// change must fail at compile time rather than surprise downstream callers.
var (
	_ func(int) (*sgn.Encoder, error)                            = sgn.NewEncoder
	_ func([]byte, byte) []byte                                  = sgn.CipherADFL
	_ func() string                                              = sgn.RandomOperand
	_ func() byte                                                = sgn.GetRandomByte
	_ func(int) []byte                                           = sgn.GetRandomBytes
	_ func() bool                                                = sgn.CoinFlip
	_ func(sgn.SCHEMA) string                                    = sgn.GetSchemaTable
	_ func() string                                              = sgn.GetRandomSafeAssembly
	_ func() string                                              = sgn.RandomLabel
	_ func(*sgn.Encoder, int) error                              = (*sgn.Encoder).SetArchitecture
	_ func(*sgn.Encoder) int                                     = (*sgn.Encoder).GetArchitecture
	_ func(*sgn.Encoder, []byte) ([]byte, error)                 = (*sgn.Encoder).Encode
	_ func(*sgn.Encoder, []byte, sgn.RandomSeed) ([]byte, error) = (*sgn.Encoder).EncodeWithSeed
	_ func(*sgn.Encoder, []byte, int, sgn.SCHEMA) []byte         = (*sgn.Encoder).SchemaCipher
	_ func(*sgn.Encoder, int) sgn.SCHEMA                         = (*sgn.Encoder).NewCipherSchema
	_ func(*sgn.Encoder, int) (string, error)                    = (*sgn.Encoder).NewDecoderAssembly
	_ func(*sgn.Encoder, []byte) ([]byte, error)                 = (*sgn.Encoder).AddADFLDecoder
	_ func(*sgn.Encoder, []byte, sgn.SCHEMA) ([]byte, error)     = (*sgn.Encoder).AddSchemaDecoder
	_ func(*sgn.Encoder) string                                  = (*sgn.Encoder).GenerateGarbageAssembly
	_ func(*sgn.Encoder) ([]byte, error)                         = (*sgn.Encoder).GenerateGarbageInstructions
	_ func(*sgn.Encoder, string) string                          = (*sgn.Encoder).GetRandomUnsafeAssembly
	_ func(*sgn.Encoder, int) *sgn.INSTRUCTION                   = (*sgn.Encoder).GetRandomUnsafeMnemonic
	_ func(*sgn.Encoder, string) string                          = (*sgn.Encoder).GetRandomOperandValue
	_ func(*sgn.Encoder) (float64, error)                        = (*sgn.Encoder).CalculateAverageGarbageInstructionSize
	_ func(*sgn.Encoder) string                                  = (*sgn.Encoder).GetRandomFunctionAssembly
	_ func(sgn.Encoder, int) string                              = sgn.Encoder.GetRandomRegister
	_ func(sgn.Encoder) string                                   = sgn.Encoder.GetRandomStackAddress
	_ func(sgn.Encoder) string                                   = sgn.Encoder.GetStackPointer
	_ func(sgn.Encoder) string                                   = sgn.Encoder.GetBasePointer
	_ func(sgn.Encoder, int, ...string) (string, error)          = sgn.Encoder.GetSafeRandomRegister
	_ func(sgn.Encoder, string) ([]byte, bool)                   = sgn.Encoder.Assemble
	_ func(sgn.Encoder, string) int                              = sgn.Encoder.GetAssemblySize
	_ func(sgn.Encoder) []byte                                   = sgn.Encoder.GenerateIPToStack
	_ func(sgn.Encoder, []byte) ([]byte, error)                  = sgn.Encoder.AddCallOver
	_ func(sgn.Encoder, []byte) ([]byte, error)                  = sgn.Encoder.AddJmpOver
	_ func(sgn.Encoder, []byte) ([]byte, error)                  = sgn.Encoder.AddCondJmpOver
	_ func(sgn.Encoder) ([]byte, error)                          = sgn.Encoder.GenerateGarbageJump
	_ func(*sgn.INSTRUCTION, int) string                         = (*sgn.INSTRUCTION).GetRandomMatchingOperandType
	_ []string                                                   = sgn.OPERANDS
	_ map[int]string                                             = sgn.STUB
	_ []string                                                   = sgn.ConditionalJumpMnemonics
	_ []string                                                   = sgn.SafeGarbageInstructions
	_ []string                                                   = sgn.SupportedOperandTypes
	_ map[int][]byte                                             = sgn.SafeRegisterPrefix
	_ map[int][]byte                                             = sgn.SafeRegisterSuffix
	_ []byte                                                     = sgn.X86_REG_SAVE_PREFIX
	_ []byte                                                     = sgn.X86_REG_SAVE_SUFFIX
	_ []byte                                                     = sgn.X64_REG_SAVE_PREFIX
	_ []byte                                                     = sgn.X64_REG_SAVE_SUFFIX
	_ map[int][]sgn.REG                                          = sgn.REGS
	_ [sgn.RandomSeedSize]byte                                   = sgn.RandomSeed{}
)

const (
	_ string = sgn.X86_DECODER_STUB
	_ string = sgn.X64_DECODER_STUB
	_ string = sgn.INSTRUCTIONS
	_ int    = sgn.RandomSeedSize
)

func compileEncoderFieldTypes(encoder *sgn.Encoder) {
	var _ int = encoder.ObfuscationLimit
	var _ bool = encoder.PlainDecoder
	var _ byte = encoder.Seed
	var _ int = encoder.EncodingCount
	var _ bool = encoder.SaveRegisters
}

func compileRegisterFieldTypes(register sgn.REG) {
	var _ string = register.Full
	var _ string = register.Extended
	var _ string = register.High
	var _ string = register.Low
	var _ int = register.Arch
}

func compileInstructionFieldTypes(instruction sgn.INSTRUCTION) {
	var _ string = instruction.Mnemonic
	var _ bool = instruction.V64
	var _ bool = instruction.V32
	var _ []struct {
		Types []string `json:"Types"`
	} = instruction.Operands
}

func compileSchemaFieldTypes(schema sgn.SCHEMA) {
	var _ string = schema[0].OP
	var _ []byte = schema[0].Key
}

func TestExportedSourceAPICompatibility(t *testing.T) {
	if got := len(sgn.RandomSeed{}); got != sgn.RandomSeedSize {
		t.Fatalf("RandomSeed length = %d, want RandomSeedSize %d", got, sgn.RandomSeedSize)
	}
}
