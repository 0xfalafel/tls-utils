use std::io::{self, Write};
use std::{thread, time::Duration};
use colored::Colorize;

pub fn loading_animation(message: &str) {
    let ascii_braille = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

    loop {
        for b in ascii_braille {
            eprint!("\r{} {}", b.green(), message);
            let _ = io::stderr().flush();
            thread::sleep(Duration::from_millis(130));
        }
    }
}