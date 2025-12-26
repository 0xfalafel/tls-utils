use std::path::PathBuf;
use std::fs;

use colored::Colorize;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::BigUint;
// use num_bigint::BigUint;

enum Key {
    Public(RsaPublicKey),
    Private(RsaPrivateKey),
}

/// Parse the PEM content from PKCS1 or PKCS8 into an `RsaPrivateKey`
fn parse_private_key_pem(file_content: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs1_pem(file_content)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(file_content))
        .map_err(|_| "Failed to parse PEM content".to_owned())
}

/// Parse the PEM content from PKCS1 or PKCS8 into an `RsaPublicKey`
fn parse_public_key_pem(file_content: &str) -> Result<RsaPublicKey, String> {
    RsaPublicKey::from_pkcs1_pem(file_content)
        .or_else(|_| RsaPublicKey::from_public_key_pem(file_content)) // pkcs8 ?
        .map_err(|_| "Failed to parse PEM content".to_owned())
}

/// Parse the DER content from PKCS1 or PKCS8 into an `RsaPrivateKey`
fn parse_private_key_der(file_content: &[u8]) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs1_der(file_content)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(file_content))
        .map_err(|_| "Failed to parse DER content".to_owned())
}

/// Parse the DER content from PKCS1 or PKCS8 into an `RsaPublicKey`
fn parse_public_key_der(file_content: &[u8]) -> Result<RsaPublicKey, String> {
    RsaPublicKey::from_pkcs1_der(file_content)
        .or_else(|_| RsaPublicKey::from_public_key_der(file_content))
        .map_err(|_| "Failed to parse DER content".to_owned())
}

/// Read a key file (PEM or DER) and return a RsaPrivateKey or RsaPublicKey
fn read_key(file: &PathBuf) -> Result<Key, String> {

    let file_content = fs::read(file)
        .map_err(|_| format!("Failed to read the content of {}", file.display()))?;

    // Parsing DER file (PKCS1 or PKCS8)

    match parse_private_key_der(&file_content) {
        Err(_err_msg) => {},
        Ok(private_key) => {
            return Ok(Key::Private(private_key))
        },
    }

    match parse_public_key_der(&file_content) {
        Err(_err_msg) => {},
        Ok(public_key) => {
            return Ok(Key::Public(public_key))
        },
    }

    // Parsing PEM files

    // PEM are ASCII, so decoding them as UTF-8 should work
    let file_content_utf8 = String::from_utf8(file_content)
        .map_err(|_| "Failed to decode file data")?;

    match parse_private_key_pem(&file_content_utf8) {
        Ok(private_key) => return Ok(Key::Private(private_key)),
        Err(_) => {}
    }

    match parse_public_key_pem(&file_content_utf8) {
        Ok(public_key) => return Ok(Key::Public(public_key)),
        Err(_) => {},
    }

    Err(format!("Failed to parse the content of {}", file.display()).to_string())
}

/// Inspect the content of a key
pub fn key(keyfile: &PathBuf, pubout: &Option<PathBuf>, der: bool) -> Result<(), String> {
    
    if !keyfile.exists() {
        return Err(format!("No such file: {}", keyfile.display()));
    }
    
    let mut key: Key = read_key(keyfile)?;
    println!("{}", format_key(&mut key));

    if let Key::Private(ref mut private_key) = key {
        // Export public key file
        if let Some(pubkey_path) = pubout {
            return export_pubkey(pubkey_path, &private_key, der)
        }
    }

    Ok(())
}

fn format_key(key: &mut Key) -> String {
    // Print info about the key

    let key_size = match &key {
        Key::Private(private_key) => private_key.n().bits(),
        Key::Public(public_key) => public_key.n().bits(),
    };

    let msg = match &key {
        Key::Private(private_key) => format!(
            "Private-Key: ({} bit, {} primes)\n", key_size, private_key.primes().len()
        ),
        Key::Public(_) => format!(
            "Public-Key: ({} bit)\n", key_size
        ),
    };
    let mut key_info_string = format!("{}", msg.magenta().bold());

    // Print info common on both private and public key
    key_info_string.push_str(
        &format_modulus(&key)
    );

    key_info_string.push_str(
        &format_public_exponent(&key)
    );

    // Print private key informations
    if let Key::Private(ref mut private_key) = key {
        // TODO: handle error, precompute can fail
        private_key.precompute().expect("Failed to precompute private key values");

        key_info_string.push_str("\n");
        key_info_string.push_str(&format_private_exponent(&private_key));
        print_primes(&private_key);
        print_exponents(&private_key);
        print_coefficient(&private_key);
        
    }
    key_info_string
}

fn export_pubkey(pubkey_path: &PathBuf, private_key: &RsaPrivateKey, der: bool) -> Result<(), String> {
    let pubkey = RsaPublicKey::from(private_key);

    // write the public key to `pubkey_path`
    match der {
        false => pubkey.write_pkcs1_pem_file(pubkey_path, LineEnding::default()),
        true  => pubkey.write_pkcs1_der_file(pubkey_path),
    }
        .map_err(|_| format!("Failed to write private key to {}", pubkey_path.display()))?;

    eprintln!("Public key written to {}", 
        format!("{}", pubkey_path.display())
        .yellow().bold());

    Ok(())
}

fn format_modulus(key: &Key) -> String {
    let modulus = match key {
        Key::Public(key) => key.n(),
        Key::Private(key) => key.n(),
    };

    let hex_modulus = format_hex(modulus);
    format!("{}\n{}\n", "modulus (n):".blue().bold(), hex_modulus)
}

fn format_public_exponent(key: &Key) -> String {
    let exponent = match key {
        Key::Public(key) => key.e(),
        Key::Private(key) => key.e(),
    };

    format!("{} {} (0x{:x})", "public exponent (e):".blue().bold(), exponent, exponent)
}

fn format_private_exponent(private_key: &RsaPrivateKey) -> String {
    let modulus = private_key.d();
    let hex_modulus = format_hex(modulus);
    format!("{}\n{}\n", "private exponent (d):".blue().bold(), hex_modulus)
}

fn print_primes(private_key: &RsaPrivateKey) {
    let primes = private_key.primes();
    let p = primes.iter().nth(0).unwrap();
    let q = primes.iter().nth(1).unwrap();

    let p_hex = format_hex(p);
    let q_hex = format_hex(q);
    println!("{}\n{}\n", "prime1 (p):".blue().bold(), p_hex);
    println!("{}\n{}\n", "prime2 (q):".blue().bold(), q_hex);
}

fn print_exponents(private_key: &RsaPrivateKey) {
    if let Some(dp) = private_key.dp() {
        println!("{}\n{}\n", "exponent1 (dp):".blue().bold(), format_hex(dp));
    }

    if let Some(dq) = private_key.dq() {
        println!("{}\n{}\n", "exponent2 (dq):".blue().bold(), format_hex(dq));
    }
}

fn print_coefficient(private_key: &RsaPrivateKey) {
    if let Some(crt_coefficient) = private_key.crt_coefficient() {
        println!("{}\n{}", "coefficient:".blue().bold(), format_hex(&crt_coefficient));
    }
}

fn format_hex(number: &BigUint) -> String {
    let mut n_chars: usize = number.bits() / 4; // / 8 bits * 2 char per byte

    // pad if we miss a 0 at the start
    if n_chars % 2 != 0 {
        n_chars = n_chars+1;
    }

    // print the number as hex in a string
    let hex= format!("{:0>n_chars$x}", number);

    // format it in openssl style
    let mut result = String::from("    ");
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte = std::str::from_utf8(chunk).unwrap();
        result.push_str(byte);
        // Add a colon after each byte except the last one
        if (i + 1) != 0 && (i + 1) < hex.len() / 2 {
            result.push(':');
        }
        // Add a newline after every 15 bytes
        if (i + 1) % 15 == 0 {
            result.push_str("\n    ");
        }
    }
    result
}   