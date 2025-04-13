use std::path::PathBuf;
use std::fs;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PrivateKeyParts;
use rsa::RsaPrivateKey;

/// Inspect the content of a key
pub fn key(keyfile: &PathBuf) -> Result<(), String> {
    
    if !keyfile.exists() {
        return Err(format!("No such file: {}", keyfile.display()));
    }

    let file_content = fs::read_to_string(keyfile)
        .map_err(|_| format!("Failed to read the content of {}", keyfile.display()))?;

    let private_key = RsaPrivateKey::from_pkcs1_pem(&file_content)
        .map_err(|_| "Failed to parse PEM content")?;

    println!("primes:");
    for prime in private_key.primes() {
        println!("{}", prime);
    }

    Ok(())
}