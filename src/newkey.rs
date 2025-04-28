use std::thread;
use std::path::PathBuf;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use colored::Colorize;
use rsa::pkcs8::LineEnding;
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;

use crate::util::loading_animation;

/// Generate a new private key
pub fn newkey(privkey_file: &PathBuf, outpub: &Option<PathBuf>,size: &Option<u16>, der: &bool, pkcs8: &bool) -> Result<(), String> {

    let size: u16 = match *size {
        Some(s) if 512 | 1024 | 2048 | 4096 == s => s,
        None => 2048,
        _ => return Err("Invalid key size. Valid RSA key size are: 1024, 2048, 4096.".to_string())
    };

    let run_animation = Arc::new(AtomicBool::new(true));
    let run_animation_clone = Arc::clone(&run_animation);

    // small animation while the private key is generated
    let animation = thread::spawn(move || {
        let key_size = format!("{} bits", size);
        loading_animation(
            format!("Generating a {} private key.", key_size.blue()).as_ref(),
            run_animation_clone
        );
    });

    let priv_key = RsaPrivateKey::new(&mut OsRng, usize::from(size))
        .map_err(|_| "Failed to generate Private Key.")?;

    // end the animation
    run_animation.store(false, Ordering::Relaxed);
    let _ = animation.join();

    // write the private key to `privkey_file`
    write_private_key(&priv_key, &privkey_file, *pkcs8, *der)?;

    let privkey_file = format!("{}", privkey_file.display());
    eprintln!("Private key written to {}", privkey_file.yellow().bold());

    if let Some(pubkey_file) = outpub {
        let pubkey = RsaPublicKey::from(&priv_key);

        // write the private key to `privkey_file`
        pubkey
            .write_pkcs1_pem_file(pubkey_file, LineEnding::default())
            .map_err(|_| format!("Failed to write private key to {}", pubkey_file.display()))?;

        eprintln!("Public key written to {}", 
            format!("{}", pubkey_file.display())
            .yellow().bold());
    }

    Ok(())
}

/// Write the private key to a file
fn write_private_key(
    priv_key: &RsaPrivateKey,
    file_path: &PathBuf,
    pkcs8: bool,
    der: bool,
) -> Result<(), String> {

    let err_msg = format!("Failed to write private key to {}", file_path.display());

    match (pkcs8, der) {
        (true, false)  => priv_key.write_pkcs8_pem_file(file_path, LineEnding::default())
            .map_err(|_| err_msg),
        (false, false) => priv_key.write_pkcs1_pem_file(file_path, LineEnding::default())
            .map_err(|_| err_msg),
        (true, true)   => priv_key.write_pkcs8_der_file(file_path)
            .map_err(|_| err_msg),
        (false, true)  => priv_key.write_pkcs1_der_file(file_path)
            .map_err(|_| err_msg),
    }
}