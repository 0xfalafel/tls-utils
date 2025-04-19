use std::path::PathBuf;
use rcgen::{CertificateParams, KeyPair};
use crate::key::read_private_key;

/// Generate a new Certificate using an existing RSA private key
pub fn newcert(keyfile: &PathBuf, domain: &str) -> Result<(), String> {
    // Read the private key from file
    //let private_key = read_private_key(keyfile)?;

    let subject_alt_names = vec![domain.to_string()];

    let cert_params = CertificateParams::new(subject_alt_names)
        .map_err(|_| "Failed to initalize the certificate")?;

    //let private_key = read_private_key(keyfile)?;
    let key_pair = KeyPair::generate()
        .map_err(|_| "Failed to generate certificate key")?;

    let cert = cert_params.self_signed(&key_pair)
        .map_err(|_| "Failed to generate certificate")?;

    println!("{}", cert.pem());
    println!("{}", key_pair.serialize_pem());

    Ok(())
}