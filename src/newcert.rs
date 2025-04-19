use std::path::PathBuf;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use crate::key::read_private_key;

/// Generate a new Certificate using an existing RSA private key
pub fn newcert(keyfile: &PathBuf, domain: &str) -> Result<(), String> {
    // Read the private key from file
    //let private_key = read_private_key(keyfile)?;

    let subject_alt_names = vec![domain.to_string()];
    
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

    println!("{}", cert.pem());
    println!("{}", key_pair.serialize_pem());

    Ok(())
}