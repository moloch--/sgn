package sgn_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	sgn "github.com/moloch--/sgn/pkg"
)

type seededCompatibilityCase struct {
	name             string
	architecture     int
	obfuscationLimit int
	plainDecoder     bool
	adflSeed         byte
	encodingCount    int
	saveRegisters    bool
	randomSeed       sgn.RandomSeed
	payload          []byte
}

func TestEncodeWithSeedDeterministicMatrix(t *testing.T) {
	for _, testCase := range seededCompatibilityCases() {
		t.Run(testCase.name, func(t *testing.T) {
			first := newSeededEncoder(t, testCase)
			second := newSeededEncoder(t, testCase)
			originalPayload := append([]byte(nil), testCase.payload...)

			firstOutput, err := first.EncodeWithSeed(testCase.payload, testCase.randomSeed)
			if err != nil {
				t.Fatalf("first EncodeWithSeed(%s): %v", describeSeededCase(testCase), err)
			}
			secondOutput, err := second.EncodeWithSeed(testCase.payload, testCase.randomSeed)
			if err != nil {
				t.Fatalf("second EncodeWithSeed(%s): %v", describeSeededCase(testCase), err)
			}

			if !bytes.Equal(firstOutput, secondOutput) {
				t.Fatal(outputMismatch("fixed-seed replay", testCase, firstOutput, secondOutput))
			}
			if len(firstOutput) == 0 {
				t.Fatalf("EncodeWithSeed(%s) returned an empty output", describeSeededCase(testCase))
			}
			if first.Seed != second.Seed || first.EncodingCount != second.EncodingCount {
				t.Fatalf(
					"fixed-seed final state mismatch (%s): first seed=%d count=%d, second seed=%d count=%d",
					describeSeededCase(testCase), first.Seed, first.EncodingCount, second.Seed, second.EncodingCount,
				)
			}
			if first.EncodingCount != 1 {
				t.Fatalf("EncodeWithSeed(%s) final EncodingCount = %d, want 1", describeSeededCase(testCase), first.EncodingCount)
			}
			if testCase.encodingCount == 1 && first.Seed != testCase.adflSeed {
				t.Fatalf("EncodeWithSeed(%s) final Seed = %d, want unchanged seed %d", describeSeededCase(testCase), first.Seed, testCase.adflSeed)
			}
			assertUnchangedEncoderOptions(t, first, testCase)
			assertUnchangedEncoderOptions(t, second, testCase)
			if !bytes.Equal(testCase.payload, originalPayload) {
				t.Fatalf("EncodeWithSeed(%s) mutated payload: got %x, want %x", describeSeededCase(testCase), testCase.payload, originalPayload)
			}
		})
	}
}

// This vector was produced by the unmodified upstream Rust port at d914ab2,
// using its public Encoder.EncodeWith method and ChaCha20Rng. It prevents the
// native oracle and Wasm build from drifting together while still agreeing
// with each other.
func TestUpstreamRustGoldenVector(t *testing.T) {
	vectors := []struct {
		architecture int
		wantLength   int
		wantDigest   string
		wantSeed     byte
	}{
		{64, 728, "6803eae70a07a1cd38d0b23a4cabd9c9e26120fcddd5d56fb09eb50ff870ee4a", 53},
		{32, 449, "a8506a658cd1b2c285f49b3dc7ba15ab0f520d9a4ca8df7972e654c13e0169ed", 3},
	}

	for _, vector := range vectors {
		t.Run(fmt.Sprintf("x%d", vector.architecture), func(t *testing.T) {
			testCase := seededCompatibilityCase{
				name:             "upstream_d914ab2",
				architecture:     vector.architecture,
				obfuscationLimit: 32,
				plainDecoder:     false,
				adflSeed:         0xa7,
				encodingCount:    3,
				saveRegisters:    true,
				randomSeed:       repeatedRandomSeed(0x42),
				payload:          []byte("fixed-seed compatibility payload"),
			}

			encoder := newSeededEncoder(t, testCase)
			output, err := encoder.EncodeWithSeed(testCase.payload, testCase.randomSeed)
			if err != nil {
				t.Fatalf("EncodeWithSeed(%s): %v", describeSeededCase(testCase), err)
			}

			digest := sha256.Sum256(output)
			if len(output) != vector.wantLength || fmt.Sprintf("%x", digest) != vector.wantDigest {
				t.Fatalf(
					"upstream d914ab2 output drifted: got len=%d sha256=%x, want len=%d sha256=%s",
					len(output), digest, vector.wantLength, vector.wantDigest,
				)
			}
			if encoder.Seed != vector.wantSeed || encoder.EncodingCount != 1 {
				t.Fatalf(
					"upstream d914ab2 final state drifted: got seed=%d count=%d, want seed=%d count=1",
					encoder.Seed, encoder.EncodingCount, vector.wantSeed,
				)
			}
		})
	}
}

func TestEncodeWithSeedConcurrentFreshEncoders(t *testing.T) {
	const workersPerCase = 4
	testCases := seededCompatibilityCases()[:4]
	type result struct {
		caseIndex int
		worker    int
		output    []byte
		seed      byte
		count     int
		err       error
	}

	start := make(chan struct{})
	results := make(chan result, len(testCases)*workersPerCase)
	for caseIndex, testCase := range testCases {
		for worker := 0; worker < workersPerCase; worker++ {
			go func(caseIndex, worker int, testCase seededCompatibilityCase) {
				<-start
				encoder, err := configuredEncoder(testCase)
				if err != nil {
					results <- result{caseIndex: caseIndex, worker: worker, err: err}
					return
				}
				output, err := encoder.EncodeWithSeed(testCase.payload, testCase.randomSeed)
				results <- result{
					caseIndex: caseIndex,
					worker:    worker,
					output:    output,
					seed:      encoder.Seed,
					count:     encoder.EncodingCount,
					err:       err,
				}
			}(caseIndex, worker, testCase)
		}
	}
	close(start)

	first := make([]*result, len(testCases))
	for range len(testCases) * workersPerCase {
		current := <-results
		testCase := testCases[current.caseIndex]
		if current.err != nil {
			t.Errorf("concurrent worker %d EncodeWithSeed(%s): %v", current.worker, describeSeededCase(testCase), current.err)
			continue
		}
		if first[current.caseIndex] == nil {
			copyOfCurrent := current
			first[current.caseIndex] = &copyOfCurrent
			continue
		}

		reference := first[current.caseIndex]
		if !bytes.Equal(current.output, reference.output) {
			t.Errorf("concurrent worker %d: %s", current.worker, outputMismatch("fixed-seed concurrent replay", testCase, reference.output, current.output))
		}
		if current.seed != reference.seed || current.count != reference.count {
			t.Errorf(
				"concurrent worker %d final state mismatch (%s): got seed=%d count=%d, worker %d seed=%d count=%d",
				current.worker, describeSeededCase(testCase), current.seed, current.count,
				reference.worker, reference.seed, reference.count,
			)
		}
	}
}

func TestEncodeUsesFreshCryptographicEntropy(t *testing.T) {
	const attempts = 5
	payload := []byte("production entropy smoke test payload")
	outputs := make([][]byte, 0, attempts)

	for attempt := 0; attempt < attempts; attempt++ {
		encoder, err := sgn.NewEncoder(64)
		if err != nil {
			t.Fatalf("NewEncoder(64), attempt %d: %v", attempt, err)
		}
		encoder.ObfuscationLimit = 50
		encoder.PlainDecoder = false
		encoder.Seed = 0xa5
		encoder.EncodingCount = 2
		encoder.SaveRegisters = true

		output, err := encoder.Encode(payload)
		if err != nil {
			t.Fatalf("Encode, attempt %d: %v", attempt, err)
		}
		outputs = append(outputs, output)
	}

	for _, output := range outputs[1:] {
		if !bytes.Equal(output, outputs[0]) {
			return
		}
	}

	digests := make([]string, 0, len(outputs))
	for _, output := range outputs {
		digest := sha256.Sum256(output)
		digests = append(digests, hex.EncodeToString(digest[:]))
	}
	t.Fatalf("Encode returned identical output in all %d fresh-encoder attempts; SHA-256 digests: %s", attempts, strings.Join(digests, ", "))
}

func TestNativeRustWASMCompatibility(t *testing.T) {
	oracle := os.Getenv("SGN_NATIVE_ORACLE")
	if oracle == "" {
		t.Skip("set SGN_NATIVE_ORACLE to a built native compat_oracle binary")
	}
	info, err := os.Stat(oracle)
	if err != nil {
		t.Fatalf("SGN_NATIVE_ORACLE %q is not a built native compat_oracle binary: %v", oracle, err)
	}
	if info.IsDir() {
		t.Fatalf("SGN_NATIVE_ORACLE %q is a directory, want a built native compat_oracle binary", oracle)
	}

	for _, testCase := range seededCompatibilityCases() {
		t.Run(testCase.name, func(t *testing.T) {
			encoder := newSeededEncoder(t, testCase)
			wasmOutput, err := encoder.EncodeWithSeed(testCase.payload, testCase.randomSeed)
			if err != nil {
				t.Fatalf("WebAssembly EncodeWithSeed(%s): %v", describeSeededCase(testCase), err)
			}

			nativeOutput, nativeSeed, nativeCount := runNativeOracle(t, oracle, testCase)
			if !bytes.Equal(wasmOutput, nativeOutput) {
				t.Fatal(outputMismatch("native Rust/WebAssembly", testCase, nativeOutput, wasmOutput))
			}
			if encoder.Seed != nativeSeed || encoder.EncodingCount != nativeCount {
				t.Fatalf(
					"native Rust/WebAssembly final state mismatch (%s): native seed=%d count=%d, WebAssembly seed=%d count=%d",
					describeSeededCase(testCase), nativeSeed, nativeCount, encoder.Seed, encoder.EncodingCount,
				)
			}
		})
	}
}

func seededCompatibilityCases() []seededCompatibilityCase {
	return []seededCompatibilityCase{
		{
			name:         "x86_plain_empty_zero",
			architecture: 32, obfuscationLimit: 0, plainDecoder: true,
			adflSeed: 0x00, encodingCount: 1, saveRegisters: false,
			randomSeed: repeatedRandomSeed(0x00), payload: nil,
		},
		{
			name:         "x64_schema_one_byte_ff",
			architecture: 64, obfuscationLimit: 1, plainDecoder: false,
			adflSeed: 0xff, encodingCount: 1, saveRegisters: true,
			randomSeed: repeatedRandomSeed(0xff), payload: []byte{0x00},
		},
		{
			name:         "x86_schema_odd_two_layers",
			architecture: 32, obfuscationLimit: 9, plainDecoder: false,
			adflSeed: 0x01, encodingCount: 2, saveRegisters: false,
			randomSeed: ascendingRandomSeed(), payload: []byte{0x00, 0x7f, 0xff},
		},
		{
			name:         "x64_plain_aligned_two_layers",
			architecture: 64, obfuscationLimit: 50, plainDecoder: true,
			adflSeed: 0xfe, encodingCount: 2, saveRegisters: true,
			randomSeed: descendingRandomSeed(), payload: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:         "x86_plain_aligned_safe_ff",
			architecture: 32, obfuscationLimit: 1, plainDecoder: true,
			adflSeed: 0xff, encodingCount: 2, saveRegisters: true,
			randomSeed: alternatingRandomSeed(0x00, 0xff), payload: []byte{0, 1, 2, 3, 4, 5, 6, 7},
		},
		{
			name:         "x64_schema_odd_zero_seed",
			architecture: 64, obfuscationLimit: 9, plainDecoder: false,
			adflSeed: 0x00, encodingCount: 1, saveRegisters: false,
			randomSeed: alternatingRandomSeed(0xff, 0x00), payload: []byte{1, 3, 5, 7, 9, 11, 13},
		},
		{
			name:         "x86_schema_aligned_max_obfuscation",
			architecture: 32, obfuscationLimit: 50, plainDecoder: false,
			adflSeed: 0x80, encodingCount: 1, saveRegisters: true,
			randomSeed: alternatingRandomSeed(0x55, 0xaa), payload: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		{
			name:         "x64_plain_odd_no_obfuscation",
			architecture: 64, obfuscationLimit: 0, plainDecoder: true,
			adflSeed: 0x7f, encodingCount: 2, saveRegisters: false,
			randomSeed: alternatingRandomSeed(0xa5, 0x5a), payload: []byte{0x90, 0x00, 0x90, 0xff, 0xcc},
		},
	}
}

func newSeededEncoder(t *testing.T, testCase seededCompatibilityCase) *sgn.Encoder {
	t.Helper()
	encoder, err := configuredEncoder(testCase)
	if err != nil {
		t.Fatalf("configure encoder (%s): %v", describeSeededCase(testCase), err)
	}
	return encoder
}

func configuredEncoder(testCase seededCompatibilityCase) (*sgn.Encoder, error) {
	encoder, err := sgn.NewEncoder(testCase.architecture)
	if err != nil {
		return nil, err
	}
	encoder.ObfuscationLimit = testCase.obfuscationLimit
	encoder.PlainDecoder = testCase.plainDecoder
	encoder.Seed = testCase.adflSeed
	encoder.EncodingCount = testCase.encodingCount
	encoder.SaveRegisters = testCase.saveRegisters
	return encoder, nil
}

func assertUnchangedEncoderOptions(t *testing.T, encoder *sgn.Encoder, testCase seededCompatibilityCase) {
	t.Helper()
	if got := encoder.GetArchitecture(); got != testCase.architecture {
		t.Errorf("EncodeWithSeed(%s) changed architecture to %d", describeSeededCase(testCase), got)
	}
	if encoder.ObfuscationLimit != testCase.obfuscationLimit {
		t.Errorf("EncodeWithSeed(%s) changed ObfuscationLimit to %d", describeSeededCase(testCase), encoder.ObfuscationLimit)
	}
	if encoder.PlainDecoder != testCase.plainDecoder {
		t.Errorf("EncodeWithSeed(%s) changed PlainDecoder to %t", describeSeededCase(testCase), encoder.PlainDecoder)
	}
	if encoder.SaveRegisters != testCase.saveRegisters {
		t.Errorf("EncodeWithSeed(%s) changed SaveRegisters to %t", describeSeededCase(testCase), encoder.SaveRegisters)
	}
}

func runNativeOracle(t *testing.T, oracle string, testCase seededCompatibilityCase) ([]byte, byte, int) {
	t.Helper()
	arguments := []string{
		strconv.Itoa(testCase.architecture),
		strconv.Itoa(testCase.obfuscationLimit),
		boolArgument(testCase.plainDecoder),
		strconv.Itoa(int(testCase.adflSeed)),
		strconv.Itoa(testCase.encodingCount),
		boolArgument(testCase.saveRegisters),
		hex.EncodeToString(testCase.randomSeed[:]),
		hex.EncodeToString(testCase.payload),
	}

	command := exec.Command(oracle, arguments...)
	stdout, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			t.Fatalf(
				"native compat_oracle failed (%s): %v; stderr=%q",
				describeSeededCase(testCase), err, string(exitError.Stderr),
			)
		}
		t.Fatalf("start native compat_oracle %q (%s): %v", oracle, describeSeededCase(testCase), err)
	}

	line := strings.TrimSuffix(string(stdout), "\n")
	line = strings.TrimSuffix(line, "\r")
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("native compat_oracle returned more than one line (%s): %q", describeSeededCase(testCase), string(stdout))
	}
	fields := strings.Split(line, "\t")
	if len(fields) != 3 {
		t.Fatalf("native compat_oracle returned %d tab-separated fields, want 3 (%s): %q", len(fields), describeSeededCase(testCase), line)
	}

	output, err := hex.DecodeString(fields[0])
	if err != nil {
		t.Fatalf("native compat_oracle output field is not hexadecimal (%s): %q: %v", describeSeededCase(testCase), fields[0], err)
	}
	seed, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		t.Fatalf("native compat_oracle finalSeed is not a decimal byte (%s): %q: %v", describeSeededCase(testCase), fields[1], err)
	}
	count, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		t.Fatalf("native compat_oracle finalCount is not a decimal uint32 (%s): %q: %v", describeSeededCase(testCase), fields[2], err)
	}
	return output, byte(seed), int(count)
}

func outputMismatch(label string, testCase seededCompatibilityCase, want, got []byte) string {
	wantDigest := sha256.Sum256(want)
	gotDigest := sha256.Sum256(got)
	difference := firstDifferentByte(want, got)
	detail := fmt.Sprintf("first difference at byte %d", difference)
	if difference < len(want) && difference < len(got) {
		detail = fmt.Sprintf("byte %d: want 0x%02x, got 0x%02x", difference, want[difference], got[difference])
	} else {
		detail = fmt.Sprintf("common prefix length %d, then one output ended", difference)
	}
	return fmt.Sprintf(
		"%s output mismatch (%s): %s; want len=%d sha256=%x, got len=%d sha256=%x",
		label, describeSeededCase(testCase), detail, len(want), wantDigest, len(got), gotDigest,
	)
}

func firstDifferentByte(left, right []byte) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

func describeSeededCase(testCase seededCompatibilityCase) string {
	return fmt.Sprintf(
		"arch=%d obf=%d plain=%s adfl=%d count=%d safe=%s rng=%x payload=%x",
		testCase.architecture,
		testCase.obfuscationLimit,
		boolArgument(testCase.plainDecoder),
		testCase.adflSeed,
		testCase.encodingCount,
		boolArgument(testCase.saveRegisters),
		testCase.randomSeed,
		testCase.payload,
	)
}

func boolArgument(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func repeatedRandomSeed(value byte) (seed sgn.RandomSeed) {
	for index := range seed {
		seed[index] = value
	}
	return seed
}

func ascendingRandomSeed() (seed sgn.RandomSeed) {
	for index := range seed {
		seed[index] = byte(index)
	}
	return seed
}

func descendingRandomSeed() (seed sgn.RandomSeed) {
	for index := range seed {
		seed[index] = byte(0xff - index)
	}
	return seed
}

func alternatingRandomSeed(first, second byte) (seed sgn.RandomSeed) {
	for index := range seed {
		if index%2 == 0 {
			seed[index] = first
		} else {
			seed[index] = second
		}
	}
	return seed
}
