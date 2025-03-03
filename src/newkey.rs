use std::path::PathBuf;

use rsa::pkcs8::LineEnding;
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPrivateKey;

pub fn newkey(output: &Option<PathBuf>, size: &Option<u16>) -> Result<(), String> {

    let size: u16 = match *size {
        Some(s) if 1024 | 2048 | 4096 == s => s,
        None => 4096,
        _ => return Err("Invalid key size. Valid RSA key size are: 1024, 2048, 4096.".to_string())
    };

    let priv_key = RsaPrivateKey::new(&mut OsRng, usize::from(size))
        .map_err(|_| "Failed to generate Private Key.")?;

    
    let privkey_file = match output {
        Some(path) => path.clone(),
        None => return Err("An output file is required to store the private key".to_string()),
    };


    priv_key.write_pkcs1_pem_file(privkey_file, LineEnding::default());


    let _pub_key = RsaPublicKey::from(&priv_key);

    Ok(())
}