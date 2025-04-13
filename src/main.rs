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
        /// write the key to this file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// size of the key generated. 
        #[arg(short, long)]
        size: Option<u16>
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::NewKey { output, size } => {
            if let Err(error_msg) = newkey(output, size) {
                eprintln!("{}", error_msg.red());
            }
        }
    }
}
