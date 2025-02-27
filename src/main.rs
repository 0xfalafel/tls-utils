use std::path::PathBuf;
use clap::{Parser, Subcommand};


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// generate a new asymetric key (i.e RSA)
    NewKey {
        /// write the key to this file
        #[arg(short, long)]
        output: Option<PathBuf>,

        #[arg(short, long)]
        size: Option<u16>
    },
}

fn main() {
    let cli = Cli::parse();

    println!("Hello, world!");
    println!("u16 max: {}", u16::MAX);
}
