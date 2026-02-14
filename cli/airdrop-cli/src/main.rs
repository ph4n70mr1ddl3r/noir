#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[allow(dead_code, unreachable_pub)]
mod build_tree;
#[allow(dead_code, unreachable_pub)]
mod claim;
#[allow(dead_code, unreachable_pub)]
mod common;
#[allow(dead_code, unreachable_pub)]
mod prove;

#[derive(Parser)]
#[command(name = "airdrop")]
#[command(about = "Noir ZK Airdrop CLI tools", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
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
