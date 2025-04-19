use std::{fs, path::PathBuf};
use rcgen::{CertificateParams, KeyPair};

/// Generate a new Certificate using an existing RSA private key
pub fn newcert(keyfile: &PathBuf, domain: &str) -> Result<(), String> {

    let key_data = fs::read_to_string(keyfile)
        .map_err(|_| format!("Failed to read the content of {}", keyfile.display()))?;

    // Parse the PEM data
    let key_pair = KeyPair::from_pem(&key_data)
        .map_err(|_| "Failed to read key from PEM")?;

    let subject_alt_names = vec![domain.to_string()];

    let cert_params = CertificateParams::new(subject_alt_names)
        .map_err(|_| "Failed to initalize the certificate")?;

    // let key_pair = KeyPair::generate()
    //     .map_err(|_| "Failed to generate certificate key")?;

    let cert = cert_params.self_signed(&key_pair)
        .map_err(|_| "Failed to generate certificate")?;

    println!("{}", cert.pem());
    println!("{}", key_pair.serialize_pem());

    Ok(())
}