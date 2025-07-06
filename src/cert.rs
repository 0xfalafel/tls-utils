use std::path::PathBuf;
use std::fs;
use x509_parser::prelude::parse_x509_pem;

/// Generate a new Certificate using an existing RSA private key
pub fn cert(cert_file: &PathBuf) -> Result<(), String> {
    
    let file_content = fs::read(cert_file)
        .map_err(|_| format!("Failed to read the content of {}", cert_file.display()))?;

    if let Ok((_remaining_bytes, pem_certificate)) = parse_x509_pem(&file_content) {
        if let Ok(certificate) = pem_certificate.parse_x509() {
            println!("version: {}",certificate.version());
        }
    }        

    Ok(())
}