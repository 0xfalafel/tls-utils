use std::{fs, path::PathBuf};
use rcgen::{CertificateParams, KeyPair};

/// Generate a new Certificate using an existing RSA private key
pub fn newcert(domain: &str, keyfile: &Option<PathBuf>) -> Result<(), String> {

    let key_pair = get_keypair(keyfile)?;

    let subject_alt_names = vec![domain.to_string()];

    let cert_params = CertificateParams::new(subject_alt_names)
        .map_err(|_| "Failed to initalize the certificate")?;

    let cert = cert_params.self_signed(&key_pair)
        .map_err(|_| "Failed to generate certificate")?;

    println!("{}", cert.pem());
    println!("{}", key_pair.serialize_pem());

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
        let key = KeyPair::generate().map_err(|_| "Failed to generate private key")?;
        Ok(key)
    }
}