use std::path::PathBuf;
use std::fs;
use colored::Colorize;
use x509_parser::prelude::parse_x509_pem;
use x509_parser::num_bigint::BigUint;

// Take the OID list from here:
// https://learn.microsoft.com/fr-fr/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier

/// Read a certificate data
pub fn read_certificate(cert_file: &PathBuf) -> Result<(), String> {
    
    let file_content = fs::read(cert_file)
        .map_err(|_| format!("Failed to read the content of {}", cert_file.display()))?;

    if let Ok((_remaining_bytes, pem_certificate)) = parse_x509_pem(&file_content) {
        if let Ok(certificate) = pem_certificate.parse_x509() {
            println!("{} {}", "Version:".blue().bold(), certificate.version());           
            println!("{}\n\t{}", "Serial number:".blue().bold(), format_hex(&certificate.serial));
            println!("{} {:?}", "Signature Algorithm:".blue().bold(), certificate.signature_algorithm)

        }
    }        

    Ok(())
}


fn format_hex(number: &BigUint) -> String {
    let mut n_chars: usize = (number.bits() / 4).try_into().unwrap(); // / 8 bits * 2 char per byte

    // pad if we miss a 0 at the start
    if n_chars % 2 != 0 {
        n_chars = n_chars+1;
    }

    // print the number as hex in a string
    let hex= format!("{:0>n_chars$x}", number);

    // format it in openssl style
    let mut result = String::new();
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte = std::str::from_utf8(chunk).unwrap();
        result.push_str(byte);
        // Add a colon after each byte except the last one
        if (i + 1) != 0 && (i + 1) < hex.len() / 2 {
            result.push(':');
        }
    }
    result
}   
