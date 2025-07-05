use std::path::PathBuf;
use std::fs;

use colored::Colorize;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::BigUint;
// use num_bigint::BigUint;

/// Parse the PEM content from PKCS1 or PKCS8 into an `RsaPrivateKey`
fn parse_private_key_pem(file_content: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs1_pem(file_content)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(file_content))
        .map_err(|_| "Failed to parse PEM content".to_owned())
}

/// Parse the DER content from PKCS1 or PKCS8 into an `RsaPrivateKey`
fn parse_private_key_der(file_content: &[u8]) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs1_der(file_content)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(file_content))
        .map_err(|_| "Failed to parse DER content".to_owned())
}

pub fn read_private_key(file: &PathBuf) -> Result<RsaPrivateKey, String> {

    let file_content = fs::read(file)
        .map_err(|_| format!("Failed to read the content of {}", file.display()))?;

    match parse_private_key_der(&file_content) {
        Err(_err_msg) => {},
        Ok(private_key) => {return Ok(private_key)},
    }

    let file_content_utf8 = String::from_utf8(file_content)
        .map_err(|_| "Failed to decode file data")?;

    let private_key = parse_private_key_pem(&file_content_utf8)
        .map_err(|_| "Failed to parse private key")?;

    Ok(private_key)
}

/// Inspect the content of a key
pub fn key(keyfile: &PathBuf, pubout: &Option<PathBuf>, der: bool) -> Result<(), String> {
    
    if !keyfile.exists() {
        return Err(format!("No such file: {}", keyfile.display()));
    }
    
    let mut private_key: RsaPrivateKey = read_private_key(keyfile)?;
    // TODO: handle error, precompute can fail
    private_key.precompute().expect("Failed to precompute private key values");

    let key_size = match private_key.n().bits() {
        n if n <= 512 => 512,
        n if n <= 1024 => 1024,
        n if n <= 2048 => 2048,
        _ => 4096
    };

    let msg = format!(
        "Private-Key: ({} bit, {} primes)", key_size, private_key.primes().len()
    );
    println!("{}", msg.magenta().bold());

    // Export public key file
    if let Some(pubkey_path) = pubout {
        return export_pubkey(pubkey_path, private_key, der)
    }
    
    print_modulus(&private_key);
    print_public_exponent(&private_key);
    print_private_exponent(&private_key);
    print_primes(&private_key);
    print_exponents(&private_key);
    print_coefficient(&private_key);

    Ok(())
}

fn export_pubkey(pubkey_path: &PathBuf, private_key: RsaPrivateKey, der: bool) -> Result<(), String> {
    let pubkey = RsaPublicKey::from(&private_key);

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

fn print_modulus(private_key: &RsaPrivateKey) {
    let modulus = private_key.n();
    let hex_modulus = format_hex(modulus);
    println!("{}\n{}\n", "modulus (n):".blue().bold(), hex_modulus);
}

fn print_public_exponent(private_key: &RsaPrivateKey) {
    let exponent = private_key.e();
    println!("{} {} (0x{:x})\n", "public exponent (e):".blue().bold(), exponent, exponent);
}

fn print_private_exponent(private_key: &RsaPrivateKey) {
    let modulus = private_key.d();
    let hex_modulus = format_hex(modulus);
    println!("{}\n{}\n", "private exponent (d):".blue().bold(), hex_modulus);
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
        println!("{}\n{}\n", "coefficient:".blue().bold(), format_hex(&crt_coefficient));
    }
}

fn format_hex(number: &BigUint) -> String {
    // print the number as hex in a string
    let hex_number= format!("{:0258x}", number);

    // group by hex
    let bytes: Vec<&str> = hex_number.as_bytes()
        .chunks(2)
        .map(|byte| str::from_utf8(byte).unwrap())
        .collect();

    // Group the hex by line of 15
    bytes
        .chunks(15)
        .map(|chunk| chunk.join(":"))
        .collect::<Vec<String>>()
        .into_iter()
        .map(|chunk| format!("    {chunk}"))
        .collect::<Vec<String>>()
        .join(":\n")
}   