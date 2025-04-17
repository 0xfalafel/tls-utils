use std::path::PathBuf;
use std::fs;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use rsa::traits::PrivateKeyParts;

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

fn read_private_key(file: &PathBuf) -> Result<RsaPrivateKey, String> {

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
pub fn key(keyfile: &PathBuf, pubout: &Option<PathBuf>) -> Result<(), String> {
    
    if !keyfile.exists() {
        return Err(format!("No such file: {}", keyfile.display()));
    }

    let private_key = read_private_key(keyfile)?;

    println!("primes:");
    for prime in private_key.primes() {
        println!("{}", prime);
    }

    Ok(())
}