use std::path::PathBuf;
use std::fs;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PrivateKeyParts;
use rsa::RsaPrivateKey;

/// Inspect the content of a key
pub fn key(keyfile: &PathBuf) -> Result<(), String> {
    
    if !keyfile.exists() {
        return Err(format!("No such file: {}", keyfile.display()));
    }

    let file_content = fs::read_to_string(keyfile)
        .map_err(|_| format!("Failed to read the content of {}", keyfile.display()))?;

    let res = RsaPrivateKey::from_pkcs1_pem(&file_content);

    let private_key = if res.is_err() {
        match RsaPrivateKey::from_pkcs8_pem(&file_content) {
            Ok(private_key) => private_key,
            Err(_) => return Err("Failed to parse PEM content".to_owned()),
        }
    } else {
        res.unwrap()
    };

    println!("primes:");
    for prime in private_key.primes() {
        println!("{}", prime);
    }

    Ok(())
}