use std::thread;
use std::path::PathBuf;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use colored::Colorize;
use rsa::pkcs8::LineEnding;
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPrivateKey;

use crate::util::loading_animation;

pub fn newkey(output: &Option<PathBuf>, size: &Option<u16>) -> Result<(), String> {

    let size: u16 = match *size {
        Some(s) if 1024 | 2048 | 4096 == s => s,
        None => 2048,
        _ => return Err("Invalid key size. Valid RSA key size are: 1024, 2048, 4096.".to_string())
    };

    let run_animation = Arc::new(AtomicBool::new(true));
    let run_animation_clone = Arc::clone(&run_animation);

    // small animation to help the user wait
    let animation = thread::spawn(move || {
        let key_size = format!("{} bits", size);
        loading_animation(
            format!("Generating a {} private key.", key_size.blue()).as_ref(),
            run_animation_clone
        );
    });

    let priv_key = RsaPrivateKey::new(&mut OsRng, usize::from(size))
        .map_err(|_| "Failed to generate Private Key.")?;

    // close the animation
    run_animation.store(false, Ordering::Relaxed);
    let _ = animation.join();

    let privkey_file = match output {
        Some(path) => path.clone(),
        None => return Err("An output file is required to store the private key".to_string()),
    };

    if priv_key.write_pkcs1_pem_file(privkey_file.clone(), LineEnding::default()).is_err() {
        return Err(format!("Failed to write private key to {}", privkey_file.display()));
    }

    let privkey_file = format!("{}", privkey_file.display());
    eprintln!("Private key written to {}", privkey_file.yellow().bold());

    let _pub_key = RsaPublicKey::from(&priv_key);

    Ok(())
}