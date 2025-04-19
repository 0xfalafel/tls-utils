use std::io::Write;
use std::{fs, path::PathBuf};
use std::fs::File;
use colored::Colorize;
use rcgen::{CertificateParams, KeyPair};

/// Generate a new Certificate using an existing RSA private key
pub fn newcert(domain: &str, keyfile: &Option<PathBuf>) -> Result<(), String> {

    let key_pair = get_keypair(keyfile)?;

    let subject_alt_names = vec![domain.to_string()];

    let cert_params = CertificateParams::new(subject_alt_names)
        .map_err(|_| "Failed to initalize the certificate")?;

    let cert = cert_params.self_signed(&key_pair)
        .map_err(|_| "Failed to generate certificate")?;    

    let cert_file = domain.to_owned() + ".crt";

    let mut crt = File::create(cert_file.clone())
        .map_err(|_| format!("Failed to create file {}", cert_file))?;

    crt.write_all(cert.pem().as_bytes())
        .map_err(|_| format!("Failed to write to {}", cert_file))?;

    eprintln!("{}", format!("Certificate written to {}", cert_file).yellow());

    if keyfile.is_none() {
        let key_file = domain.to_string() + ".key";

        let mut key_pem = File::create(key_file.clone())
            .map_err(|_| format!("Failed to create file {}", key_file))?;

        key_pem.write_all(key_pair.serialize_pem().as_bytes())
            .map_err(|_| format!("Failed to write to {}", key_file))?;

        eprintln!("{}", format!("Key written to {}", key_file).yellow());
    }

    Ok(())
}


fn get_keypair(keyfile: &Option<PathBuf>) -> Result<KeyPair, String>{
    if let Some(key_path) = keyfile {
        let key_data = fs::read_to_string(key_path)
            .map_err(|_| format!("Failed to read the content of {}", key_path.display()))?;
    
        // Parse the PEM data
        let key = KeyPair::from_pem(&key_data)
            .map_err(|_| "Failed to read private key from PEM")?;
        Ok(key)
        
    } else {
        let key = KeyPair::generate()
            .map_err(|_| "Failed to generate private key")?;
        Ok(key)
    }
}