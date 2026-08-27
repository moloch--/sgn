//! Machine-readable native oracle for Go/WebAssembly compatibility tests.

use sgn::{Encoder, RANDOM_SEED_SIZE};
use std::process::ExitCode;

fn usage() -> String {
    "usage: compat_oracle <arch> <obfuscation_limit> <plain:0|1> <adfl_seed> \
     <encoding_count> <safe:0|1> <64-hex-char-rng-seed> <payload-hex>"
        .into()
}

fn parse_bool(value: &str, name: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("{name} must be 0 or 1")),
    }
}

fn parse_adfl_seed(value: &str) -> Result<u8, String> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16)
    } else {
        value.parse::<u16>()
    }
    .map_err(|error| format!("invalid ADFL seed: {error}"))?;

    u8::try_from(parsed).map_err(|_| "ADFL seed must be between 0 and 255".into())
}

fn decode_hex(value: &str, name: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("{name} must contain an even number of hex digits"));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(index, pair)| {
            let high =
                hex_nibble(pair[0]).ok_or_else(|| format!("invalid {name} at byte {index}"))?;
            let low =
                hex_nibble(pair[1]).ok_or_else(|| format!("invalid {name} at byte {index}"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(value: &[u8]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 8 {
        return Err(usage());
    }

    let arch = args[0]
        .parse::<u32>()
        .map_err(|error| format!("invalid architecture: {error}"))?;
    if arch != 32 && arch != 64 {
        return Err("architecture must be 32 or 64".into());
    }

    let obfuscation_limit = args[1]
        .parse::<i32>()
        .map_err(|error| format!("invalid obfuscation limit: {error}"))?;
    if obfuscation_limit < 0 {
        return Err("obfuscation limit must be nonnegative".into());
    }

    let plain_decoder = parse_bool(&args[2], "plain")?;
    let adfl_seed = parse_adfl_seed(&args[3])?;
    let encoding_count = args[4]
        .parse::<u32>()
        .map_err(|error| format!("invalid encoding count: {error}"))?;
    if encoding_count < 1 {
        return Err("encoding count must be at least 1".into());
    }
    let save_registers = parse_bool(&args[5], "safe")?;

    if args[6].len() != RANDOM_SEED_SIZE * 2 {
        return Err(format!(
            "random seed must contain exactly {} hex digits",
            RANDOM_SEED_SIZE * 2
        ));
    }
    let random_seed = decode_hex(&args[6], "random seed")?;
    let random_seed: [u8; RANDOM_SEED_SIZE] = random_seed
        .try_into()
        .map_err(|_| "random seed has an invalid length".to_string())?;
    let payload = decode_hex(&args[7], "payload")?;

    let mut encoder = Encoder {
        architecture: arch,
        obfuscation_limit,
        plain_decoder,
        seed: adfl_seed,
        encoding_count,
        save_registers,
    };
    let output = encoder
        .encode_with_seed(&payload, random_seed)
        .map_err(|error| format!("encode failed: {error}"))?;

    println!(
        "{}\t{}\t{}",
        encode_hex(&output),
        encoder.seed,
        encoder.encoding_count
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
