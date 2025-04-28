use std::path::PathBuf;
use clap::{Parser, Subcommand};
use colored::Colorize;

mod newkey;
mod key;
mod util;

use newkey::newkey;
use key::key;

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
        #[arg(value_name = "PRIVATE KEY")]
        output: PathBuf,

        /// write the public key to this file
        #[arg(short='p', long, value_name = "PUBLIC KEY")]
        outpub: Option<PathBuf>,

        /// size of the key generated (512, 1024, 2048 or 4096). 
        #[arg(short, long)]
        size: Option<u16>,

        /// encode the key in DER format
        #[arg(short, long)]
        der: bool,        

        /// use pkcs8 format, default is pkcs1
        #[arg(long)]
        pkcs8: bool,
    },

    /// Inspect a key file
    Key {
        /// Key to read
        keyfile: PathBuf,

        /// Write the public key to this file
        #[arg(short, long)]
        pubout: Option<PathBuf>,

        /// Write the public key in DER format
        #[arg(short, long)]
        der: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::NewKey { 
            output, outpub, size, der, pkcs8, 
        } => {
            
            let res = newkey(
                output, outpub, size, der, pkcs8
            );
            
            if let Err(error_msg) = res {
                eprintln!("{}", error_msg.red());
            }
        },
        Commands::Key { keyfile , pubout, der } => {
            let res = key(keyfile, pubout, *der);

            if let Err(error_msg) = res {
                eprintln!("{}", error_msg.red());
            }
        }
    }
}
