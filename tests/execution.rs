//! End-to-end validation: deterministically encode and execute a corpus of x64
//! shellcode, confirming that every variant decodes itself and runs the
//! original payload. This is the Linux analogue of the original project's
//! Windows `VirtualAlloc` stress test.
//!
//! Each encoded variant executes in a child copy of this test binary. A broken
//! decoder can therefore fault or time out without taking its replay metadata
//! down with it in the parent process.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use iced_x86::code_asm::*;
use sgn::{Encoder, RANDOM_SEED_SIZE};
use std::fmt::Write as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const MAGIC: u64 = 0x1337_c0de;
/// mov eax, 0x1337c0de ; ret
const PAYLOAD: &[u8] = &[0xb8, 0xde, 0xc0, 0x37, 0x13, 0xc3];
/// Assert the normal SysV AMD64 function-entry alignment, then fall through.
/// A misaligned safe wrapper executes UD2 in the isolated child process.
const SYSV_ENTRY_ALIGNMENT_PAYLOAD: &[u8] = &[
    0x48, 0x89, 0xe0, // mov rax, rsp
    0x83, 0xe0, 0x0f, // and eax, 0xf
    0x83, 0xf8, 0x08, // cmp eax, 8
    0x74, 0x02, // je aligned
    0x0f, 0x0b, // ud2
];
/// Exercise an aligned SIMD stack access after a normal SysV payload prologue.
/// A wrapper that flips entry alignment faults on MOVAPS, matching the Sliver
/// Linux/amd64 failure mode.
const SYSV_ALIGNED_STACK_ACCESS_PAYLOAD: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // sub rsp, 8
    0x0f, 0x28, 0x04, 0x24, // movaps xmm0, [rsp]
    0x48, 0x83, 0xc4, 0x08, // add rsp, 8
];
const ENTRY_RAX: u32 = 0x1111_1111;
const ENTRY_RBX: u32 = 0x2222_2222;
const ENTRY_R10: u32 = 0x3333_3333;
const ENTRY_R15: u32 = 0x4444_4444;
/// Clobber representative caller- and callee-saved GPRs, then fall through.
const GPR_CLOBBER_PAYLOAD: &[u8] = &[
    0x31, 0xc0, // xor eax, eax
    0x31, 0xdb, // xor ebx, ebx
    0x45, 0x31, 0xd2, // xor r10d, r10d
    0x45, 0x31, 0xff, // xor r15d, r15d
];
/// Verify that the safe suffix restored the trampoline's known entry values.
const GPR_RESTORE_CONTINUATION: &[u8] = &[
    0x3d, 0x11, 0x11, 0x11, 0x11, // cmp eax, ENTRY_RAX
    0x75, 0x20, // jne failed
    0x81, 0xfb, 0x22, 0x22, 0x22, 0x22, // cmp ebx, ENTRY_RBX
    0x75, 0x18, // jne failed
    0x41, 0x81, 0xfa, 0x33, 0x33, 0x33, 0x33, // cmp r10d, ENTRY_R10
    0x75, 0x0f, // jne failed
    0x41, 0x81, 0xff, 0x44, 0x44, 0x44, 0x44, // cmp r15d, ENTRY_R15
    0x75, 0x06, // jne failed
    0xb8, 0xde, 0xc0, 0x37, 0x13, // mov eax, MAGIC
    0xc3, // ret
    0x0f, 0x0b, // failed: ud2
];
const SLIVER_LARGE_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
const EXECUTION_MODES: &str = include_str!("execution_modes.tsv");
const CHILD_PATH_ENV: &str = "SGN_X64_EXECUTION_CHILD_PATH";
const CHILD_SKIP_CODE: i32 = 77;
const CHILD_TIMEOUT_SECONDS: u32 = 2;

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

/// Wraps `shell` in a trampoline that preserves the System-V callee-saved
/// registers (RBX, RBP, R12-R15) across execution. SGN shellcode freely
/// clobbers general-purpose registers, so the test harness must isolate the
/// call itself.
fn trampoline(shell: &[u8]) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    a.push(rbx).unwrap();
    a.push(rbp).unwrap();
    a.push(r12).unwrap();
    a.push(r13).unwrap();
    a.push(r14).unwrap();
    a.push(r15).unwrap();
    // The function entry is RSP%16 == 8. Six pushes keep it there, so reserve
    // one slot to satisfy the SysV caller-side alignment rule before CALL.
    a.sub(rsp, 8).unwrap();
    a.mov(eax, ENTRY_RAX).unwrap();
    a.mov(ebx, ENTRY_RBX).unwrap();
    a.mov(r10d, ENTRY_R10).unwrap();
    a.mov(r15d, ENTRY_R15).unwrap();
    let mut target = a.create_label();
    a.call(target).unwrap();
    a.add(rsp, 8).unwrap();
    a.pop(r15).unwrap();
    a.pop(r14).unwrap();
    a.pop(r13).unwrap();
    a.pop(r12).unwrap();
    a.pop(rbp).unwrap();
    a.pop(rbx).unwrap();
    a.ret().unwrap();
    a.set_label(&mut target).unwrap();
    a.db(shell).unwrap();
    a.assemble(0).unwrap()
}

/// Maps `shell` (wrapped in a register-preserving trampoline) as executable
/// memory and calls it. Returns `None` if the environment refuses executable
/// mappings. The alarm bounds malformed variants that loop rather than fault.
unsafe fn run(shell: &[u8]) -> Option<u64> {
    let code = trampoline(shell);
    let code = code.as_slice();
    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let len = code.len().div_ceil(page) * page;

    // Try a directly-RWX mapping first; fall back to RW + mprotect(RWX).
    // SGN's decoder writes into its own encoded bytes while executing.
    let mut mem = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if mem == libc::MAP_FAILED {
        mem = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if mem == libc::MAP_FAILED {
            return None;
        }
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
        if libc::mprotect(
            mem,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            libc::munmap(mem, len);
            return None;
        }
    } else {
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
    }

    let func: extern "C" fn() -> u64 = std::mem::transmute(mem);
    libc::alarm(CHILD_TIMEOUT_SECONDS);
    let result = func();
    libc::alarm(0);
    libc::munmap(mem, len);
    Some(result)
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

fn encode_case(mode: ExecutionMode, adfl_seed: u8, random_seed: [u8; 32]) -> Vec<u8> {
    let payload = payload_for_mode(mode);
    encode_payload_case(mode, adfl_seed, random_seed, payload)
}

fn encode_payload_case(
    mode: ExecutionMode,
    adfl_seed: u8,
    random_seed: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut encoder = Encoder {
        architecture: 64,
        obfuscation_limit: mode.obfuscation_limit,
        plain_decoder: mode.plain_decoder,
        seed: adfl_seed,
        encoding_count: mode.encoding_count,
        save_registers: mode.save_registers,
    };
    encoder
        .encode_with_seed(payload, random_seed)
        .unwrap_or_else(|error| {
            panic!(
                "x64 corpus encode failed: {}; error={error}",
                replay_tuple(mode, adfl_seed, &random_seed, payload)
            )
        })
}

fn sliver_safe_schema_mode() -> ExecutionMode {
    execution_modes()
        .into_iter()
        .find(|mode| mode.name == "sliver-safe-schema")
        .expect("shared execution corpus must include the exact Sliver safe schema profile")
}

fn payload_for_mode(mode: ExecutionMode) -> &'static [u8] {
    if mode.save_registers {
        SYSV_ENTRY_ALIGNMENT_PAYLOAD
    } else {
        PAYLOAD
    }
}

fn replay_tuple(
    mode: ExecutionMode,
    adfl_seed: u8,
    random_seed: &[u8; RANDOM_SEED_SIZE],
    payload: &[u8],
) -> String {
    let payload_hex = if payload.len() <= 256 {
        format!(" payload={}", encode_hex(payload))
    } else {
        String::new()
    };
    format!(
        "arch=64 mode={} obf={} plain={} adfl={adfl_seed:#04x} count={} safe={} rng={} \
         payload_len={} payload_fnv1a64={:016x}{}",
        mode.name,
        mode.obfuscation_limit,
        mode.plain_decoder,
        mode.encoding_count,
        mode.save_registers,
        encode_hex(random_seed),
        payload.len(),
        fnv1a64(payload),
        payload_hex,
    )
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

fn describe_status(status: ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit_code={code}"),
        (None, Some(signal)) => format!("signal={signal} core_dumped={}", status.core_dumped()),
        (None, None) => format!("status={status:?}"),
    }
}

fn execute_in_child(
    test_binary: &Path,
    shell_path: &Path,
) -> std::io::Result<std::process::Output> {
    Command::new(test_binary)
        .args([
            "--exact",
            "x64_execution_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_PATH_ENV, shell_path)
        .output()
}

fn assert_sliver_profile_executes(case_name: &str, payload: &[u8], continuation: &[u8]) {
    let mode = sliver_safe_schema_mode();
    let adfl_seed = 0;
    let random_seed = [0; RANDOM_SEED_SIZE];
    let test_binary = std::env::current_exe().expect("locate current x64 execution test binary");
    let test_directory = TestDirectory(
        std::env::temp_dir().join(format!("sgn64_{case_name}_test_{}", std::process::id())),
    );
    std::fs::create_dir_all(&test_directory.0).expect("create Sliver profile test directory");
    let shell_path = test_directory.0.join("shellcode.bin");

    let encoded = encode_payload_case(mode, adfl_seed, random_seed, payload);
    let output_length = encoded.len();
    let output_digest = fnv1a64(&encoded);
    let payload_digest = fnv1a64(payload);
    let continuation_digest = fnv1a64(continuation);
    let mut shell = encoded;
    shell.extend_from_slice(continuation);
    std::fs::write(&shell_path, &shell).unwrap_or_else(|error| {
        panic!(
            "write Sliver profile x64 execution case: case={case_name} mode={} arch=64 \
             obf={} plain={} adfl={adfl_seed:#04x} count={} safe={} rng={} \
             payload_len={} payload_fnv1a64={payload_digest:016x} output_len={output_length} \
             output_fnv1a64={output_digest:016x} continuation_len={} \
             continuation_fnv1a64={continuation_digest:016x}; error={error}",
            mode.name,
            mode.obfuscation_limit,
            mode.plain_decoder,
            mode.encoding_count,
            mode.save_registers,
            encode_hex(&random_seed),
            payload.len(),
            continuation.len(),
        )
    });

    let child = execute_in_child(&test_binary, &shell_path).unwrap_or_else(|error| {
        panic!(
            "start Sliver profile x64 execution child: case={case_name} mode={} arch=64 \
             obf={} plain={} adfl={adfl_seed:#04x} count={} safe={} rng={} \
             payload_len={} payload_fnv1a64={payload_digest:016x} output_len={output_length} \
             output_fnv1a64={output_digest:016x} continuation_len={} \
             continuation_fnv1a64={continuation_digest:016x}; error={error}",
            mode.name,
            mode.obfuscation_limit,
            mode.plain_decoder,
            mode.encoding_count,
            mode.save_registers,
            encode_hex(&random_seed),
            payload.len(),
            continuation.len(),
        )
    });
    if child.status.code() == Some(CHILD_SKIP_CODE) {
        let detail = format!(
            "case={case_name} mode={} arch=64 obf={} plain={} adfl={adfl_seed:#04x} \
             count={} safe={} rng={} payload_len={} payload_fnv1a64={payload_digest:016x} \
             output_len={output_length} output_fnv1a64={output_digest:016x} continuation_len={} \
             continuation_fnv1a64={continuation_digest:016x}; {}",
            mode.name,
            mode.obfuscation_limit,
            mode.plain_decoder,
            mode.encoding_count,
            mode.save_registers,
            encode_hex(&random_seed),
            payload.len(),
            continuation.len(),
            describe_status(child.status),
        );
        if execution_required() {
            panic!("executable memory is unavailable while SGN_REQUIRE_EXECUTION is set: {detail}");
        }
        eprintln!("skipped: executable memory unavailable: {detail}");
        return;
    }
    assert!(
        child.status.success(),
        "Sliver profile x64 shellcode did not decode and execute: case={case_name} mode={} \
         arch=64 obf={} plain={} adfl={adfl_seed:#04x} count={} safe={} rng={} \
         payload_len={} payload_fnv1a64={payload_digest:016x} output_len={output_length} \
         output_fnv1a64={output_digest:016x} continuation_len={} \
         continuation_fnv1a64={continuation_digest:016x}; {}; child_stdout={:?}; child_stderr={:?}",
        mode.name,
        mode.obfuscation_limit,
        mode.plain_decoder,
        mode.encoding_count,
        mode.save_registers,
        encode_hex(&random_seed),
        payload.len(),
        continuation.len(),
        describe_status(child.status),
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
}

#[test]
fn x64_execution_child() {
    let Some(path) = std::env::var_os(CHILD_PATH_ENV) else {
        return;
    };
    let shell = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("read x64 execution child payload {path:?}: {error}"));

    let Some(value) = (unsafe { run(&shell) }) else {
        std::process::exit(CHILD_SKIP_CODE);
    };
    assert_eq!(
        value & 0xffff_ffff,
        MAGIC,
        "decoded payload returned wrong value"
    );
}

#[test]
fn sliver_safe_x64_sysv_entry_alignment_executes() {
    assert_sliver_profile_executes(
        "sysv-entry-alignment",
        SYSV_ENTRY_ALIGNMENT_PAYLOAD,
        PAYLOAD,
    );
}

#[test]
fn sliver_safe_x64_aligned_stack_access_executes() {
    assert_sliver_profile_executes(
        "aligned-stack-access",
        SYSV_ALIGNED_STACK_ACCESS_PAYLOAD,
        PAYLOAD,
    );
}

#[test]
fn sliver_safe_x64_gpr_restoration_executes() {
    assert_sliver_profile_executes(
        "gpr-restoration",
        GPR_CLOBBER_PAYLOAD,
        GPR_RESTORE_CONTINUATION,
    );
}

#[test]
fn sliver_safe_x64_large_payload_executes() {
    let mut payload = vec![0x90; SLIVER_LARGE_PAYLOAD_SIZE];
    // The ADFL decoder must traverse the entire payload. Skip the NOP body at
    // execution time so this remains a decoder-size regression rather than a
    // runner-speed benchmark; the final NOP falls through the restore suffix.
    let final_nop_displacement = (SLIVER_LARGE_PAYLOAD_SIZE as i32) - 6;
    payload[0] = 0xe9;
    payload[1..5].copy_from_slice(&final_nop_displacement.to_le_bytes());
    assert_sliver_profile_executes("large-payload", &payload, PAYLOAD);
}

#[test]
fn deterministic_x64_execution_corpus() {
    let modes = execution_modes();
    let test_binary = std::env::current_exe().expect("locate current x64 execution test binary");
    let test_directory =
        TestDirectory(std::env::temp_dir().join(format!("sgn64_test_{}", std::process::id())));
    std::fs::create_dir_all(&test_directory.0).expect("create x64 execution test directory");
    let shell_path = test_directory.0.join("shellcode.bin");

    let mut runs = 0;
    for mode in modes.iter().copied() {
        for adfl_seed in 0..=u8::MAX {
            let random_seed = [adfl_seed; RANDOM_SEED_SIZE];
            let payload = payload_for_mode(mode);
            let encoded = encode_case(mode, adfl_seed, random_seed);
            let output_length = encoded.len();
            let output_digest = fnv1a64(&encoded);
            let mut shell = encoded;
            if mode.save_registers {
                // The alignment probe falls through the generated restore
                // suffix into this unencoded sentinel continuation.
                shell.extend_from_slice(PAYLOAD);
            }
            std::fs::write(&shell_path, &shell).unwrap_or_else(|error| {
                panic!(
                    "write x64 execution case: {}; output_len={output_length} \
                     output_fnv1a64={output_digest:016x}; error={error}",
                    replay_tuple(mode, adfl_seed, &random_seed, payload),
                )
            });

            let child = execute_in_child(&test_binary, &shell_path).unwrap_or_else(|error| {
                panic!(
                    "start x64 execution child: {}; output_len={output_length} \
                     output_fnv1a64={output_digest:016x}; error={error}",
                    replay_tuple(mode, adfl_seed, &random_seed, payload),
                )
            });
            if child.status.code() == Some(CHILD_SKIP_CODE) {
                let detail = format!(
                    "{}; output_len={output_length} output_fnv1a64={output_digest:016x}; {}",
                    replay_tuple(mode, adfl_seed, &random_seed, payload),
                    describe_status(child.status),
                );
                if execution_required() {
                    panic!("executable memory is unavailable while SGN_REQUIRE_EXECUTION is set: {detail}");
                }
                eprintln!("skipped: executable memory unavailable: {detail}");
                return;
            }
            assert!(
                child.status.success(),
                "x64 shellcode did not decode to the expected value: {}; output_len={output_length} \
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
