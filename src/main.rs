use std::path::PathBuf;
use clap::{Parser, Subcommand};

mod newkey;
mod util;
use colored::Colorize;
use newkey::newkey;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// generate a new asymetric key (i.e RSA)
    NewKey {
        /// write the private key to this file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// write the public key to this file
        #[arg(short='p', long)]
        outpub: Option<PathBuf>,

        /// size of the key generated (1024, 2048 or 4096). 
        #[arg(short, long)]
        size: Option<u16>
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::NewKey { output, outpub, size } => {
            if let Err(error_msg) = newkey(output, outpub, size) {
                eprintln!("{}", error_msg.red());
            }
        }
    }
}
