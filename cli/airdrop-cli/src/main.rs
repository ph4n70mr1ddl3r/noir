#![forbid(unsafe_code)]
#![allow(unreachable_pub)]

use clap::{Parser, Subcommand};

mod build_tree;
mod claim;
mod common;
mod prove;

#[derive(Parser, Debug)]
#[command(name = "airdrop")]
#[command(about = "Noir ZK Airdrop CLI tools", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    BuildTree(build_tree::Cli),
    Claim(claim::Cli),
    Prove(prove::Cli),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildTree(args) => build_tree::run(args)?,
        Commands::Claim(args) => claim::run(args)?,
        Commands::Prove(args) => prove::run(&args)?,
    }

    Ok(())
}
