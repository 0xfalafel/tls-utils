use std::path::PathBuf;
use std::fs;
use std::time::SystemTime;
use colored::Colorize;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem};
use x509_parser::public_key;

use crate::key::{Key, display_key};

// Read a certificate data
pub fn read_certificate(cert_file: &PathBuf) -> Result<(), String> {
    
    // Parse x509 certificate
    let file_content = fs::read(cert_file)
        .map_err(|_| format!("Failed to read the content of {}", cert_file.display()))?;

    let certificate = Certificate::from_der(&file_content)
        .or_else(|_| Certificate::from_pem(String::from_utf8_lossy(&file_content).into_owned()))
        .map_err(|_| format!("Failed to parse the content of {} as an x509 certificate", cert_file.display()))?;


    // Display the value of each field
    let certificate_data = certificate.tbs_certificate();

    println!("{}", "Certificate (x509):".magenta().bold());
    println!("    {} {}", "Version:".blue().bold(), (certificate_data.version() as u8) + 1);
    println!("    {}\n\t{}", "Serial number:".blue().bold(), certificate_data.serial_number());

    let algorithm = oid_to_string(&certificate.signature_algorithm().oid.to_string());
    println!("    {} {}", "Signature Algorithm:".blue().bold(), algorithm);
    println!("    {} {}", "Issuer:".blue().bold(), certificate_data.issuer().to_string().yellow().bold());

    let now = SystemTime::now();
    let not_before = certificate_data.validity().not_before.to_system_time();
    let not_after = certificate_data.validity().not_after.to_system_time();
    
    println!("    {}", "Validity:".blue().bold());

    match now {
        now if now < not_before => println!("    \t{}", "Certificate is not valid yet".red().bold()),
        now if now > not_after  => println!("    \t{}", "Certificate is expired".red().bold()),
        _ => println!("    \t{}", "Certificate is valid".green().bold()),
    }
    
    // Todo: improve the display of dates
    println!("    \t{} {}", "Not Before:".blue().bold(), certificate_data.validity().not_before);
    println!("    \t{} {}", "Not After:".blue().bold(), certificate_data.validity().not_after);

    println!("    {} {}", "Subject:".blue().bold(), certificate_data.subject().to_string().yellow().bold());
    
    println!("    {}", "Subject Public Key Info:".blue().bold());
    let public_key_info = certificate_data.subject_public_key_info();
    let pubkey_alg = oid_to_string(&public_key_info.algorithm.oid.to_string());
    println!("    \t{} {}", "Public Key Algorithm:".blue().bold(), pubkey_alg);

    if let Some(public_key_der) = public_key_info.subject_public_key.as_bytes() {
        println!("public_key_der: {:?}", public_key_der);

        if let Ok(rsa_public_key) = RsaPublicKey::from_public_key_der(public_key_der) {
            display_key(&Key::Public(rsa_public_key));
        } else {
            eprintln!("Not a rsa public key ??");
        }
    } else {
        eprintln!("No public key in the certificate");
    }

    Ok(())
}

/// Convert OID to common name
/// https://oidref.com/1.2.840.113549.1.1.1
fn oid_to_string(oid: &String) -> String {
    match oid.as_ref() {
        "1.2.840.113549.1.1.1"   => "rsaEncryption".to_string(),
        "1.2.840.113549.1.1.4"   => "md5WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.5"   => "sha1WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.10"  => "rsassaPss".to_string(),
        "1.2.840.113549.1.1.11"  => "sha256WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.12"  => "sha384WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.13"  => "sha512WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.14"  => "sha224WithRSAEncryption".to_string(),

        "1.2.840.10045.4.1"      => "ecdsa-with-SHA1".to_string(),
        "1.2.840.10045.4.3.1"    => "ecdsa-with-SHA224".to_string(),
        "1.2.840.10045.4.3.2"    => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3"    => "ecdsa-with-SHA384".to_string(),
        "1.2.840.10045.4.3.4"    => "ecdsa-with-SHA512".to_string(),

        "1.3.101.112"            => "Ed25519".to_string(),
        "1.3.101.113"            => "Ed448".to_string(),

        "1.2.840.10040.4.3"      => "dsa-with-sha1".to_string(),
        "2.16.840.1.101.3.4.3.2" => "dsa-with-sha256".to_string(),

        other => other.to_string(),
    }
}
