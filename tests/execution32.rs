//! 32-bit end-to-end execution test.
//!
//! A 64-bit process can't directly call 32-bit shellcode, so this test shells
//! out to a tiny C harness compiled with `cc -m32`. If a 32-bit toolchain isn't
//! available the test skips cleanly. Each SGN-encoded payload is wrapped in a
//! trampoline that preserves the i386 SysV callee-saved registers.

#![cfg(target_os = "linux")]

use iced_x86::code_asm::*;
use sgn::{Encoder, RANDOM_SEED_SIZE};
use std::fmt::Write as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const HARNESS_SRC: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) return 4;
    fclose(f);
    long pg = sysconf(_SC_PAGESIZE);
    long len = ((n + pg - 1) / pg) * pg;
    void *mem = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 5;
    memcpy(mem, buf, n);
    /* SGN decodes in place, so the mapping must remain writable at runtime. */
    if (mprotect(mem, len, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) return 6;
    unsigned int result;
    alarm(2);
    __asm__ volatile("call *%1" : "=a"(result) : "r"(mem) : "ecx","edx","memory","cc");
    alarm(0);
    if (result != 0x1337c0de) {
        fprintf(stderr, "decoded payload returned 0x%08x, want 0x1337c0de\n", result);
        return 1;
    }
    return 0;
}
"#;

/// mov eax, 0x1337c0de ; ret
const PAYLOAD: &[u8] = &[0xb8, 0xde, 0xc0, 0x37, 0x13, 0xc3];
const SAFE_PAYLOAD: &[u8] = &[0x90, 0x90, 0x90];
const EXECUTION_MODES: &str = include_str!("execution_modes.tsv");

#[derive(Clone, Copy, Debug)]
struct ExecutionMode {
    name: &'static str,
    obfuscation_limit: i32,
    plain_decoder: bool,
    encoding_count: u32,
    save_registers: bool,
}

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Wraps 32-bit shellcode, preserving i386 callee-saved registers.
fn trampoline32(shell: &[u8]) -> Vec<u8> {
    let mut a = CodeAssembler::new(32).unwrap();
    a.push(ebx).unwrap();
    a.push(esi).unwrap();
    a.push(edi).unwrap();
    a.push(ebp).unwrap();
    let mut target = a.create_label();
    a.call(target).unwrap();
    a.pop(ebp).unwrap();
    a.pop(edi).unwrap();
    a.pop(esi).unwrap();
    a.pop(ebx).unwrap();
    a.ret().unwrap();
    a.set_label(&mut target).unwrap();
    a.db(shell).unwrap();
    a.assemble(0).unwrap()
}

/// Compiles the harness with `cc -m32`; returns its path or `None` if the
/// toolchain is unavailable.
fn build_harness(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("harness32.c");
    let bin = dir.join("harness32");
    std::fs::write(&src, HARNESS_SRC).ok()?;
    let status = Command::new("cc")
        .args(["-m32", "-O2"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .ok()?;
    if status.success() {
        Some(bin)
    } else {
        None
    }
}

fn execution_required() -> bool {
    std::env::var_os("SGN_REQUIRE_EXECUTION").is_some()
}

fn execution_modes() -> Vec<ExecutionMode> {
    let modes: Vec<_> = EXECUTION_MODES
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let line_number = index + 1;
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                5,
                "execution mode line {line_number} has {} fields, want 5",
                fields.len()
            );

            ExecutionMode {
                name: fields[0],
                obfuscation_limit: fields[1].parse().unwrap_or_else(|error| {
                    panic!("invalid obfuscation limit on mode line {line_number}: {error}")
                }),
                plain_decoder: parse_bool(fields[2], line_number, "plain_decoder"),
                encoding_count: fields[3].parse().unwrap_or_else(|error| {
                    panic!("invalid encoding count on mode line {line_number}: {error}")
                }),
                save_registers: parse_bool(fields[4], line_number, "save_registers"),
            }
        })
        .collect();

    assert_eq!(modes.len(), 7, "execution corpus must contain 7 modes");
    modes
}

fn parse_bool(value: &str, line_number: usize, field: &str) -> bool {
    match value {
        "true" => true,
        "false" => false,
        _ => panic!("invalid {field} on mode line {line_number}: {value:?}"),
    }
}

fn payload_for_mode(mode: ExecutionMode) -> &'static [u8] {
    if mode.save_registers {
        SAFE_PAYLOAD
    } else {
        PAYLOAD
    }
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn fnv1a64(value: &[u8]) -> u64 {
    value.iter().fold(0xcbf2_9ce4_8422_2325, |digest, byte| {
        (digest ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn replay_tuple(
    mode: ExecutionMode,
    adfl_seed: u8,
    random_seed: &[u8; RANDOM_SEED_SIZE],
    payload: &[u8],
) -> String {
    format!(
        "arch=32 mode={} obf={} plain={} adfl={adfl_seed:#04x} count={} safe={} rng={} payload={}",
        mode.name,
        mode.obfuscation_limit,
        mode.plain_decoder,
        mode.encoding_count,
        mode.save_registers,
        encode_hex(random_seed),
        encode_hex(payload),
    )
}

fn describe_status(status: std::process::ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit_code={code}"),
        (None, Some(signal)) => format!("signal={signal} core_dumped={}", status.core_dumped()),
        (None, None) => format!("status={status:?}"),
    }
}

#[test]
fn x86_shellcode_executes() {
    let modes = execution_modes();
    let test_directory =
        TestDirectory(std::env::temp_dir().join(format!("sgn32_test_{}", std::process::id())));
    std::fs::create_dir_all(&test_directory.0).expect("create x86 execution test directory");

    let harness = match build_harness(&test_directory.0) {
        Some(h) => h,
        None => {
            if execution_required() {
                panic!("32-bit C toolchain is unavailable while SGN_REQUIRE_EXECUTION is set");
            }
            eprintln!("skipped: no 32-bit C toolchain (cc -m32) available");
            return;
        }
    };

    let bin = test_directory.0.join("sc.bin");

    let mut runs = 0;
    for mode in modes.iter().copied() {
        for adfl_seed in 0..=u8::MAX {
            let random_seed = [adfl_seed; RANDOM_SEED_SIZE];
            let payload = payload_for_mode(mode);
            let mut encoder = Encoder {
                architecture: 32,
                obfuscation_limit: mode.obfuscation_limit,
                plain_decoder: mode.plain_decoder,
                seed: adfl_seed,
                encoding_count: mode.encoding_count,
                save_registers: mode.save_registers,
            };
            let encoded = encoder
                .encode_with_seed(payload, random_seed)
                .unwrap_or_else(|error| {
                    panic!(
                        "x86 corpus encode failed: {}; error={error}",
                        replay_tuple(mode, adfl_seed, &random_seed, payload)
                    )
                });
            let output_length = encoded.len();
            let output_digest = fnv1a64(&encoded);
            let mut shell = encoded;
            if mode.save_registers {
                // The encoded NOPs fall through the generated restore suffix
                // into this unencoded sentinel continuation.
                shell.extend_from_slice(PAYLOAD);
            }
            let code = trampoline32(&shell);
            std::fs::write(&bin, &code).unwrap_or_else(|error| {
                panic!(
                    "write x86 execution case: {}; output_len={output_length} \
                     output_fnv1a64={output_digest:016x}; error={error}",
                    replay_tuple(mode, adfl_seed, &random_seed, payload),
                )
            });
            let child = Command::new(&harness)
                .arg(&bin)
                .output()
                .unwrap_or_else(|error| {
                    panic!(
                        "start x86 execution child: {}; output_len={output_length} \
                         output_fnv1a64={output_digest:016x}; error={error}",
                        replay_tuple(mode, adfl_seed, &random_seed, payload),
                    )
                });
            assert!(
                child.status.success(),
                "x86 shellcode did not decode to the expected value: {}; output_len={output_length} \
                 output_fnv1a64={output_digest:016x}; {}; child_stdout={:?}; child_stderr={:?}",
                replay_tuple(mode, adfl_seed, &random_seed, payload),
                describe_status(child.status),
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr),
            );
            runs += 1;
        }
    }

    assert_eq!(runs, modes.len() * (usize::from(u8::MAX) + 1));
}
