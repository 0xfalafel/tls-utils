use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::io::{self, Write};
use std::{thread, time::Duration};
use colored::Colorize;

pub fn loading_animation(message: &str, running: Arc<AtomicBool>) {
    let ascii_braille = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

    while running.load(Ordering::Relaxed) {
        for b in ascii_braille {
            eprint!("\r{} {}", b.green(), message);
            let _ = io::stderr().flush();
            thread::sleep(Duration::from_millis(130));
        }
    }
    eprintln!("\r{} {}", "⠿".green(), message);
}