//! WebAssembly host ABI for embedding SGN in runtimes such as wazero.
//!
//! The ABI owns input allocations made through [`sgn_alloc`] and retains the
//! most recent output or error until the next [`sgn_encode`] call. Hosts must
//! copy those result bytes before calling `sgn_encode` again.

use crate::{Encoder, RANDOM_SEED_SIZE};
use std::cell::RefCell;

/// Encoding completed successfully.
pub const SGN_STATUS_OK: i32 = 0;
/// One or more ABI arguments failed validation.
pub const SGN_STATUS_INVALID_ARGUMENT: i32 = 1;
/// The Rust encoder returned an error.
pub const SGN_STATUS_ENCODING_ERROR: i32 = 2;

#[derive(Clone, Copy)]
struct Allocation {
    ptr: usize,
    len: usize,
}

#[derive(Default)]
struct AbiState {
    allocations: Vec<Allocation>,
    output: Vec<u8>,
    error: Vec<u8>,
    final_seed: u8,
    final_encoding_count: u32,
}

thread_local! {
    static ABI_STATE: RefCell<AbiState> = RefCell::new(AbiState::default());
}

fn abi_pointer(ptr: i32) -> usize {
    ptr as u32 as usize
}

fn returned_pointer(bytes: &[u8]) -> i32 {
    if bytes.is_empty() {
        0
    } else {
        bytes.as_ptr() as usize as u32 as i32
    }
}

fn allocation_contains(ptr: usize, len: usize) -> bool {
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };

    ABI_STATE.with(|state| {
        state.borrow().allocations.iter().any(|allocation| {
            let Some(allocation_end) = allocation.ptr.checked_add(allocation.len) else {
                return false;
            };
            ptr >= allocation.ptr && end <= allocation_end
        })
    })
}

fn copy_allocation(ptr: i32, len: usize, name: &str) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let ptr = abi_pointer(ptr);
    if ptr == 0 || !allocation_contains(ptr, len) {
        return Err(format!(
            "{name} pointer does not reference an allocated {len}-byte range"
        ));
    }

    // SAFETY: `allocation_contains` proves the complete range belongs to a
    // live allocation returned by `sgn_alloc`. The allocation is leaked until
    // `sgn_free`, and the bytes are copied before this function returns.
    Ok(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
}

fn reset_result() {
    ABI_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.output.clear();
        state.error.clear();
        state.final_seed = 0;
        state.final_encoding_count = 0;
    });
}

fn fail(status: i32, message: impl Into<String>) -> i32 {
    ABI_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.output.clear();
        state.error = message.into().into_bytes();
        state.final_seed = 0;
        state.final_encoding_count = 0;
    });
    status
}

fn parse_bool(value: i32, name: &str) -> Result<bool, String> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(format!("{name} must be 0 or 1")),
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_impl(
    input_ptr: i32,
    input_len: i32,
    arch: i32,
    obfuscation_limit: i32,
    plain_decoder: i32,
    adfl_seed: i32,
    encoding_count: i32,
    save_registers: i32,
    rng_seed_ptr: i32,
    rng_seed_len: i32,
) -> Result<(Vec<u8>, u8, u32), (i32, String)> {
    if input_len < 0 {
        return Err((
            SGN_STATUS_INVALID_ARGUMENT,
            "input length must be nonnegative".into(),
        ));
    }
    if arch != 32 && arch != 64 {
        return Err((
            SGN_STATUS_INVALID_ARGUMENT,
            format!("architecture must be 32 or 64, got {arch}"),
        ));
    }
    if obfuscation_limit < 0 {
        return Err((
            SGN_STATUS_INVALID_ARGUMENT,
            "obfuscation limit must be nonnegative".into(),
        ));
    }
    let plain_decoder = parse_bool(plain_decoder, "plain flag")
        .map_err(|message| (SGN_STATUS_INVALID_ARGUMENT, message))?;
    if !(0..=u8::MAX as i32).contains(&adfl_seed) {
        return Err((
            SGN_STATUS_INVALID_ARGUMENT,
            "ADFL seed must be between 0 and 255".into(),
        ));
    }
    if encoding_count < 1 {
        return Err((
            SGN_STATUS_INVALID_ARGUMENT,
            "encoding count must be at least 1".into(),
        ));
    }
    let encoding_count = u32::try_from(encoding_count).map_err(|_| {
        (
            SGN_STATUS_INVALID_ARGUMENT,
            "encoding count is out of range".into(),
        )
    })?;
    let save_registers = parse_bool(save_registers, "save flag")
        .map_err(|message| (SGN_STATUS_INVALID_ARGUMENT, message))?;
    if rng_seed_len != RANDOM_SEED_SIZE as i32 {
        return Err((
            SGN_STATUS_INVALID_ARGUMENT,
            format!("random seed length must be {RANDOM_SEED_SIZE}"),
        ));
    }

    let input = copy_allocation(input_ptr, input_len as usize, "input")
        .map_err(|message| (SGN_STATUS_INVALID_ARGUMENT, message))?;
    let rng_seed = copy_allocation(rng_seed_ptr, RANDOM_SEED_SIZE, "random seed")
        .map_err(|message| (SGN_STATUS_INVALID_ARGUMENT, message))?;
    let rng_seed: [u8; RANDOM_SEED_SIZE] = rng_seed.try_into().map_err(|_| {
        (
            SGN_STATUS_INVALID_ARGUMENT,
            format!("random seed length must be {RANDOM_SEED_SIZE}"),
        )
    })?;

    let mut encoder = Encoder {
        architecture: arch as u32,
        obfuscation_limit,
        plain_decoder,
        seed: adfl_seed as u8,
        encoding_count,
        save_registers,
    };
    let output = encoder
        .encode_with_seed(&input, rng_seed)
        .map_err(|error| (SGN_STATUS_ENCODING_ERROR, error.to_string()))?;
    if output.len() > i32::MAX as usize {
        return Err((
            SGN_STATUS_ENCODING_ERROR,
            "encoded output is too large for the WebAssembly ABI".into(),
        ));
    }

    Ok((output, encoder.seed, encoder.encoding_count))
}

/// Allocates `len` zeroed bytes in guest memory and returns their pointer.
/// Returns zero for a non-positive length or an allocation failure.
#[no_mangle]
pub extern "C" fn sgn_alloc(len: i32) -> i32 {
    let Ok(len) = usize::try_from(len) else {
        return 0;
    };
    if len == 0 {
        return 0;
    }

    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(len).is_err() {
        return 0;
    }
    bytes.resize(len, 0);
    let bytes = bytes.into_boxed_slice();
    let ptr = Box::into_raw(bytes) as *mut u8 as usize;

    ABI_STATE.with(|state| {
        state.borrow_mut().allocations.push(Allocation { ptr, len });
    });
    ptr as u32 as i32
}

/// Releases an exact pointer/length pair previously returned by [`sgn_alloc`].
/// Invalid, partial, repeated, and zero-length frees are ignored.
#[no_mangle]
pub extern "C" fn sgn_free(ptr: i32, len: i32) {
    let Ok(len) = usize::try_from(len) else {
        return;
    };
    if len == 0 {
        return;
    }
    let ptr = abi_pointer(ptr);

    let found = ABI_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state
            .allocations
            .iter()
            .position(|allocation| allocation.ptr == ptr && allocation.len == len)
            .map(|index| state.allocations.swap_remove(index))
    });
    if found.is_none() {
        return;
    }

    // SAFETY: the exact live allocation was removed above, preventing a
    // repeated free. `sgn_alloc` created it as a boxed slice with this length.
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr as *mut u8,
            len,
        )));
    }
}

/// Encodes a guest-memory input buffer with explicit configuration and RNG
/// seed. Returns one of the `SGN_STATUS_*` constants above.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn sgn_encode(
    input_ptr: i32,
    input_len: i32,
    arch: i32,
    obfuscation_limit: i32,
    plain_decoder: i32,
    adfl_seed: i32,
    encoding_count: i32,
    save_registers: i32,
    rng_seed_ptr: i32,
    rng_seed_len: i32,
) -> i32 {
    reset_result();
    match encode_impl(
        input_ptr,
        input_len,
        arch,
        obfuscation_limit,
        plain_decoder,
        adfl_seed,
        encoding_count,
        save_registers,
        rng_seed_ptr,
        rng_seed_len,
    ) {
        Ok((output, final_seed, final_encoding_count)) => {
            ABI_STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.output = output;
                state.error.clear();
                state.final_seed = final_seed;
                state.final_encoding_count = final_encoding_count;
            });
            SGN_STATUS_OK
        }
        Err((status, message)) => fail(status, message),
    }
}

/// Pointer to the most recent successful encoded output, or zero when empty.
#[no_mangle]
pub extern "C" fn sgn_output_ptr() -> i32 {
    ABI_STATE.with(|state| returned_pointer(&state.borrow().output))
}

/// Length of the most recent successful encoded output.
#[no_mangle]
pub extern "C" fn sgn_output_len() -> i32 {
    ABI_STATE.with(|state| state.borrow().output.len() as i32)
}

/// Pointer to the most recent UTF-8 error message, or zero when empty.
#[no_mangle]
pub extern "C" fn sgn_error_ptr() -> i32 {
    ABI_STATE.with(|state| returned_pointer(&state.borrow().error))
}

/// Length of the most recent UTF-8 error message.
#[no_mangle]
pub extern "C" fn sgn_error_len() -> i32 {
    ABI_STATE.with(|state| state.borrow().error.len() as i32)
}

/// Final ADFL seed after the most recent successful encode.
#[no_mangle]
pub extern "C" fn sgn_final_seed() -> i32 {
    ABI_STATE.with(|state| state.borrow().final_seed as i32)
}

/// Final recursive encoding count after the most recent successful encode.
#[no_mangle]
pub extern "C" fn sgn_final_encoding_count() -> i32 {
    ABI_STATE.with(|state| state.borrow().final_encoding_count as i32)
}
