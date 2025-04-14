use std::path::PathBuf;
use std::fs;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PrivateKeyParts;
use rsa::RsaPrivateKey;

/// Parse the PEM content into an `RsaPrivateKey`
fn parse_private_key(file_content: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs1_pem(file_content)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(file_content))
        .map_err(|_| "Failed to parse PEM content".to_owned())
}

/// Inspect the content of a key
pub fn key(keyfile: &PathBuf) -> Result<(), String> {
    
    if !keyfile.exists() {
        return Err(format!("No such file: {}", keyfile.display()));
    }

    let file_content = fs::read_to_string(keyfile)
        .map_err(|_| format!("Failed to read the content of {}", keyfile.display()))?;

    let private_key = parse_private_key(&file_content)?;

    println!("primes:");
    for prime in private_key.primes() {
        println!("{}", prime);
    }

    Ok(())
}