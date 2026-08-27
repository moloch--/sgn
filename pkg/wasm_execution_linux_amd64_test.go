//go:build linux && amd64

package sgn_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sgn "github.com/moloch--/sgn/pkg"
)

const (
	x64ExecutionModeCount     = 7
	x64ExecutionTimeout       = 5 * time.Second
	x64SliverLargePayloadSize = 16 * 1024 * 1024
	x64SliverProfileADFLSeed  = byte(0)
	x64SliverProfileMode      = "sliver-safe-schema"
)

var (
	x64SentinelPayload           = []byte{0xb8, 0xde, 0xc0, 0x37, 0x13, 0xc3} // mov eax, 0x1337c0de; ret
	x64SysVEntryAlignmentPayload = []byte{
		0x48, 0x89, 0xe0, // mov rax, rsp
		0x83, 0xe0, 0x0f, // and eax, 0xf
		0x83, 0xf8, 0x08, // cmp eax, 8
		0x74, 0x02, // je aligned
		0x0f, 0x0b, // ud2
	}
	x64SysVAlignedStackAccessPayload = []byte{
		0x48, 0x83, 0xec, 0x08, // sub rsp, 8
		0x0f, 0x28, 0x04, 0x24, // movaps xmm0, [rsp]
		0x48, 0x83, 0xc4, 0x08, // add rsp, 8
	}
	x64GPRClobberPayload = []byte{
		0x31, 0xc0, // xor eax, eax
		0x31, 0xdb, // xor ebx, ebx
		0x45, 0x31, 0xd2, // xor r10d, r10d
		0x45, 0x31, 0xff, // xor r15d, r15d
	}
	x64GPRRestoreContinuation = []byte{
		0x3d, 0x11, 0x11, 0x11, 0x11, // cmp eax, 0x11111111
		0x75, 0x20, // jne failed
		0x81, 0xfb, 0x22, 0x22, 0x22, 0x22, // cmp ebx, 0x22222222
		0x75, 0x18, // jne failed
		0x41, 0x81, 0xfa, 0x33, 0x33, 0x33, 0x33, // cmp r10d, 0x33333333
		0x75, 0x0f, // jne failed
		0x41, 0x81, 0xff, 0x44, 0x44, 0x44, 0x44, // cmp r15d, 0x44444444
		0x75, 0x06, // jne failed
		0xb8, 0xde, 0xc0, 0x37, 0x13, // mov eax, 0x1337c0de
		0xc3,       // ret
		0x0f, 0x0b, // failed: ud2
	}
)

func TestWASMEncodeWithSeedX64SliverProfileEntryAlignment(t *testing.T) {
	requireX64WASMExecution(t)
	executeX64WASMSliverProfileCase(t, "sysv-entry-alignment", x64SysVEntryAlignmentPayload, x64SentinelPayload)
}

func TestWASMEncodeWithSeedX64SliverProfileAlignedStackAccess(t *testing.T) {
	requireX64WASMExecution(t)
	executeX64WASMSliverProfileCase(t, "aligned-stack-access", x64SysVAlignedStackAccessPayload, x64SentinelPayload)
}

func TestWASMEncodeWithSeedX64SliverProfileGPRRestoration(t *testing.T) {
	requireX64WASMExecution(t)
	executeX64WASMSliverProfileCase(t, "gpr-restoration", x64GPRClobberPayload, x64GPRRestoreContinuation)
}

func TestWASMEncodeWithSeedX64SliverProfileLargePayload(t *testing.T) {
	requireX64WASMExecution(t)
	payload := bytes.Repeat([]byte{0x90}, x64SliverLargePayloadSize)
	// Decode every byte, then jump over the NOP body so this measures decoder
	// correctness rather than runner speed. The final NOP reaches the suffix.
	finalNOPDisplacement := int32(x64SliverLargePayloadSize - 6)
	payload[0] = 0xe9
	payload[1] = byte(finalNOPDisplacement)
	payload[2] = byte(finalNOPDisplacement >> 8)
	payload[3] = byte(finalNOPDisplacement >> 16)
	payload[4] = byte(finalNOPDisplacement >> 24)
	executeX64WASMSliverProfileCase(t, "large-payload", payload, x64SentinelPayload)
}

type x64ExecutionMode struct {
	name             string
	obfuscationLimit int
	plainDecoder     bool
	encodingCount    int
	saveRegisters    bool
}

// TestWASMEncodeWithSeedX64ExecutionCorpus executes every embedded-Wasm
// output in a separate process. Isolation keeps a malformed decoder from
// terminating the Go test process before the exact replay inputs are logged.
func TestWASMEncodeWithSeedX64ExecutionCorpus(t *testing.T) {
	requireX64WASMExecution(t)

	modes := readX64ExecutionModes(t, filepath.Join("..", "tests", "execution_modes.tsv"))
	runner := compileX64ExecutionRunner(t)
	tempDir := t.TempDir()
	shellcodePath := filepath.Join(tempDir, "shellcode.bin")

	runs := 0
	for _, mode := range modes {
		for seedValue := 0; seedValue <= int(^byte(0)); seedValue++ {
			adflSeed := byte(seedValue)
			randomSeed := repeatedExecutionRandomSeed(adflSeed)
			payload := x64SentinelPayload
			continuation := []byte(nil)
			if mode.saveRegisters {
				payload = x64SysVEntryAlignmentPayload
				continuation = x64SentinelPayload
			}

			initialMetadata := x64ReplayMetadata(mode, adflSeed, randomSeed, payload, continuation)
			encoder, err := sgn.NewEncoder(64)
			if err != nil {
				t.Fatalf("configure x64 encoder (%s): %v", initialMetadata, err)
			}
			encoder.ObfuscationLimit = mode.obfuscationLimit
			encoder.PlainDecoder = mode.plainDecoder
			encoder.Seed = adflSeed
			encoder.EncodingCount = mode.encodingCount
			encoder.SaveRegisters = mode.saveRegisters

			output, err := encoder.EncodeWithSeed(payload, randomSeed)
			if err != nil {
				t.Fatalf("EncodeWithSeed failed (%s): %v", initialMetadata, err)
			}
			outputDigest := sha256.Sum256(output)
			executable := append([]byte(nil), output...)
			executable = append(executable, continuation...)
			metadata := fmt.Sprintf(
				"%s output_len=%d output_sha256=%x executed_len=%d final_adfl=0x%02x final_count=%d",
				initialMetadata,
				len(output),
				outputDigest,
				len(executable),
				encoder.Seed,
				encoder.EncodingCount,
			)

			if err := os.WriteFile(shellcodePath, executable, 0o600); err != nil {
				t.Fatalf("write x64 shellcode (%s): %v", metadata, err)
			}

			status, runnerOutput, err := executeX64Shellcode(runner, shellcodePath)
			if err != nil {
				t.Fatalf(
					"x64 Wasm shellcode did not execute (%s status=%s runner_output=%q): %v",
					metadata,
					status,
					runnerOutput,
					err,
				)
			}
			runs++
		}
	}

	wantRuns := len(modes) * (int(^byte(0)) + 1)
	if runs != wantRuns {
		t.Fatalf("executed %d x64 Wasm corpus cases, want %d", runs, wantRuns)
	}
}

func requireX64WASMExecution(t *testing.T) {
	t.Helper()
	if os.Getenv("SGN_REQUIRE_EXECUTION") != "1" {
		t.Skip("set SGN_REQUIRE_EXECUTION=1 to execute the x64 Wasm corpus")
	}
}

func executeX64WASMSliverProfileCase(t *testing.T, caseName string, payload, continuation []byte) {
	t.Helper()
	modes := readX64ExecutionModes(t, filepath.Join("..", "tests", "execution_modes.tsv"))
	var mode *x64ExecutionMode
	for index := range modes {
		if modes[index].name == x64SliverProfileMode {
			mode = &modes[index]
			break
		}
	}
	if mode == nil {
		t.Fatalf("shared execution corpus does not contain exact Sliver profile %q", x64SliverProfileMode)
	}

	var randomSeed sgn.RandomSeed
	encoder, err := sgn.NewEncoder(64)
	if err != nil {
		t.Fatalf("configure Sliver profile x64 encoder: %v", err)
	}
	encoder.ObfuscationLimit = mode.obfuscationLimit
	encoder.PlainDecoder = mode.plainDecoder
	encoder.Seed = x64SliverProfileADFLSeed
	encoder.EncodingCount = mode.encodingCount
	encoder.SaveRegisters = mode.saveRegisters

	payloadDigest := sha256.Sum256(payload)
	continuationDigest := sha256.Sum256(continuation)
	initialMetadata := fmt.Sprintf(
		"case=%s mode=%s arch=64 obf=%d plain=%t initial_adfl=0x%02x initial_count=%d safe=%t rng=%x payload_len=%d payload_sha256=%x continuation_len=%d continuation_sha256=%x",
		caseName,
		mode.name,
		mode.obfuscationLimit,
		mode.plainDecoder,
		x64SliverProfileADFLSeed,
		mode.encodingCount,
		mode.saveRegisters,
		randomSeed,
		len(payload),
		payloadDigest,
		len(continuation),
		continuationDigest,
	)

	output, err := encoder.EncodeWithSeed(payload, randomSeed)
	if err != nil {
		t.Fatalf("EncodeWithSeed failed for Sliver profile (%s): %v", initialMetadata, err)
	}
	outputDigest := sha256.Sum256(output)
	executable := append([]byte(nil), output...)
	executable = append(executable, continuation...)
	metadata := fmt.Sprintf(
		"%s output_len=%d output_sha256=%x executed_len=%d final_adfl=0x%02x final_count=%d",
		initialMetadata,
		len(output),
		outputDigest,
		len(executable),
		encoder.Seed,
		encoder.EncodingCount,
	)

	runner := compileX64ExecutionRunner(t)
	shellcodePath := filepath.Join(t.TempDir(), "shellcode.bin")
	if err := os.WriteFile(shellcodePath, executable, 0o600); err != nil {
		t.Fatalf("write Sliver profile x64 shellcode (%s): %v", metadata, err)
	}
	status, runnerOutput, err := executeX64Shellcode(runner, shellcodePath)
	if err != nil {
		t.Fatalf(
			"Sliver profile x64 Wasm shellcode did not execute (%s status=%s runner_output=%q): %v",
			metadata,
			status,
			runnerOutput,
			err,
		)
	}
}

func readX64ExecutionModes(t *testing.T, path string) []x64ExecutionMode {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared x64 execution modes %q: %v", path, err)
	}

	var modes []x64ExecutionMode
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			t.Fatalf("parse shared x64 execution modes %q line %d: got %d tab-separated fields, want 5", path, lineNumber, len(fields))
		}
		if fields[0] == "" {
			t.Fatalf("parse shared x64 execution modes %q line %d: mode name is empty", path, lineNumber)
		}
		if _, exists := seen[fields[0]]; exists {
			t.Fatalf("parse shared x64 execution modes %q line %d: duplicate mode %q", path, lineNumber, fields[0])
		}

		obfuscationLimit, err := strconv.Atoi(fields[1])
		if err != nil || obfuscationLimit < 0 {
			t.Fatalf("parse shared x64 execution modes %q line %d: invalid obfuscation limit %q", path, lineNumber, fields[1])
		}
		plainDecoder, err := parseExecutionBool(fields[2])
		if err != nil {
			t.Fatalf("parse shared x64 execution modes %q line %d: %v", path, lineNumber, err)
		}
		encodingCount, err := strconv.Atoi(fields[3])
		if err != nil || encodingCount < 1 {
			t.Fatalf("parse shared x64 execution modes %q line %d: invalid encoding count %q", path, lineNumber, fields[3])
		}
		saveRegisters, err := parseExecutionBool(fields[4])
		if err != nil {
			t.Fatalf("parse shared x64 execution modes %q line %d: %v", path, lineNumber, err)
		}

		seen[fields[0]] = struct{}{}
		modes = append(modes, x64ExecutionMode{
			name:             fields[0],
			obfuscationLimit: obfuscationLimit,
			plainDecoder:     plainDecoder,
			encodingCount:    encodingCount,
			saveRegisters:    saveRegisters,
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan shared x64 execution modes %q: %v", path, err)
	}
	if len(modes) != x64ExecutionModeCount {
		t.Fatalf("shared x64 execution modes %q contains %d modes, want %d", path, len(modes), x64ExecutionModeCount)
	}
	return modes
}

func parseExecutionBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("boolean %q must be true or false", value)
	}
}

func repeatedExecutionRandomSeed(value byte) (seed sgn.RandomSeed) {
	for index := range seed {
		seed[index] = value
	}
	return seed
}

func x64ReplayMetadata(
	mode x64ExecutionMode,
	adflSeed byte,
	randomSeed sgn.RandomSeed,
	payload []byte,
	continuation []byte,
) string {
	return fmt.Sprintf(
		"mode=%s arch=64 obf=%d plain=%t initial_adfl=0x%02x initial_count=%d safe=%t rng=%x payload=%x continuation=%x",
		mode.name,
		mode.obfuscationLimit,
		mode.plainDecoder,
		adflSeed,
		mode.encodingCount,
		mode.saveRegisters,
		randomSeed,
		payload,
		continuation,
	)
}

func compileX64ExecutionRunner(t *testing.T) string {
	t.Helper()
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatalf("locate C compiler for x64 execution runner: %v", err)
	}

	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "execute_x64.c")
	runnerPath := filepath.Join(tempDir, "execute_x64")
	if err := os.WriteFile(sourcePath, []byte(x64ExecutionRunnerSource), 0o600); err != nil {
		t.Fatalf("write x64 execution runner source: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		ctx,
		compiler,
		"-std=c11",
		"-O2",
		"-Wall",
		"-Wextra",
		"-Werror",
		sourcePath,
		"-o",
		runnerPath,
	).CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("compile x64 execution runner: timed out after 30s; output=%q", output)
		}
		t.Fatalf("compile x64 execution runner: %v; output=%q", err, output)
	}
	return runnerPath
}

func executeX64Shellcode(runner, shellcodePath string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), x64ExecutionTimeout)
	command := exec.CommandContext(ctx, runner, shellcodePath)
	output, err := command.CombinedOutput()
	contextErr := ctx.Err()
	cancel()
	if err == nil {
		return "exit=0", strings.TrimSpace(string(output)), nil
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return fmt.Sprintf("timeout=%s process_status=%s", x64ExecutionTimeout, x64ProcessStatus(err)), strings.TrimSpace(string(output)), err
	}
	return x64ProcessStatus(err), strings.TrimSpace(string(output)), err
}

func x64ProcessStatus(err error) string {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok {
			if waitStatus.Signaled() {
				signal := waitStatus.Signal()
				return fmt.Sprintf("signal=%s(%d) core_dumped=%t", signal, signal, waitStatus.CoreDump())
			}
			return fmt.Sprintf("exit=%d", waitStatus.ExitStatus())
		}
	}
	return fmt.Sprintf("error=%q", err)
}

const x64ExecutionRunnerSource = `
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const unsigned char trampoline[] = {
    0x53,                         /* push rbx */
    0x55,                         /* push rbp */
    0x41, 0x54,                   /* push r12 */
    0x41, 0x55,                   /* push r13 */
    0x41, 0x56,                   /* push r14 */
    0x41, 0x57,                   /* push r15 */
    0x48, 0x83, 0xec, 0x08,       /* align rsp to 16 bytes before call */
    0xb8, 0x11, 0x11, 0x11, 0x11, /* mov eax, 0x11111111 */
    0xbb, 0x22, 0x22, 0x22, 0x22, /* mov ebx, 0x22222222 */
    0x41, 0xba, 0x33, 0x33, 0x33, 0x33, /* mov r10d, 0x33333333 */
    0x41, 0xbf, 0x44, 0x44, 0x44, 0x44, /* mov r15d, 0x44444444 */
    0xe8, 0x0f, 0x00, 0x00, 0x00, /* call shellcode */
    0x48, 0x83, 0xc4, 0x08,       /* restore rsp after call */
    0x41, 0x5f,                   /* pop r15 */
    0x41, 0x5e,                   /* pop r14 */
    0x41, 0x5d,                   /* pop r13 */
    0x41, 0x5c,                   /* pop r12 */
    0x5d,                         /* pop rbp */
    0x5b,                         /* pop rbx */
    0xc3                          /* ret */
};

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <shellcode>\n", argv[0]);
        return 2;
    }

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror("fopen");
        return 3;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(file);
        return 4;
    }
    long shellcode_size_long = ftell(file);
    if (shellcode_size_long <= 0) {
        fprintf(stderr, "shellcode file is empty or unreadable\n");
        fclose(file);
        return 5;
    }
    rewind(file);

    size_t shellcode_size = (size_t)shellcode_size_long;
    if (shellcode_size > SIZE_MAX - sizeof(trampoline)) {
        fprintf(stderr, "shellcode is too large\n");
        fclose(file);
        return 6;
    }
    size_t code_size = sizeof(trampoline) + shellcode_size;
    long page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) {
        perror("sysconf");
        fclose(file);
        return 7;
    }
    size_t page_size = (size_t)page_size_long;
    if (code_size > SIZE_MAX - (page_size - 1)) {
        fprintf(stderr, "mapped code size overflow\n");
        fclose(file);
        return 8;
    }
    size_t mapping_size = ((code_size + page_size - 1) / page_size) * page_size;

    void *memory = mmap(
        NULL,
        mapping_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    if (memory == MAP_FAILED) {
        perror("mmap RWX");
        fclose(file);
        return 9;
    }

    memcpy(memory, trampoline, sizeof(trampoline));
    unsigned char *shellcode = (unsigned char *)memory + sizeof(trampoline);
    if (fread(shellcode, 1, shellcode_size, file) != shellcode_size) {
        fprintf(stderr, "short shellcode read\n");
        fclose(file);
        munmap(memory, mapping_size);
        return 10;
    }
    fclose(file);

    uint64_t (*execute)(void) = (uint64_t (*)(void))memory;
    uint64_t result = execute();
    if (munmap(memory, mapping_size) != 0) {
        perror("munmap");
        return 11;
    }
    if ((uint32_t)result != UINT32_C(0x1337c0de)) {
        fprintf(stderr, "decoded payload returned 0x%016llx, want low32=0x1337c0de\n",
                (unsigned long long)result);
        return 1;
    }
    return 0;
}
`
