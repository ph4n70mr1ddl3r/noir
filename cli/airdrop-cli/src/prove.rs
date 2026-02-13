use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use airdrop_cli::write_file_atomic;

#[derive(Parser)]
#[command(name = "prove")]
#[command(about = "Generate Noir proof from claim JSON", long_about = None)]
struct Cli {
    /// Input claim JSON file
    #[arg(short, long)]
    input: PathBuf,

    /// Noir circuit directory
    #[arg(short = 'c', long)]
    circuit: PathBuf,

    /// Output proof file
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ClaimInput {
    merkle_root: String,
    recipient: String,
    nullifier: String,
    #[allow(dead_code)]
    merkle_proof: Vec<String>,
    #[allow(dead_code)]
    merkle_indices: Vec<bool>,
}

#[derive(Debug, Serialize)]
struct ProofOutput {
    proof: Vec<String>,
    public_inputs: Vec<String>,
    #[serde(rename = "is_mock")]
    is_mock: bool,
    #[serde(rename = "timestamp")]
    timestamp: u64,
}

#[cfg(feature = "mock-proofs")]
fn generate_noir_proof(claim: &ClaimInput, circuit_path: &Path) -> Result<ProofOutput> {
    #[cfg(not(debug_assertions))]
    anyhow::bail!("Mock proofs cannot be used in release builds");

    if !circuit_path.exists() {
        anyhow::bail!("Circuit directory does not exist: {:?}", circuit_path);
    }

    let public_inputs = vec![
        claim.merkle_root.clone(),
        claim.recipient.clone(),
        claim.nullifier.clone(),
    ];

    let proof = vec!["MOCK_0x1".to_string(), "MOCK_0x2".to_string()];

    Ok(ProofOutput {
        proof,
        public_inputs,
        is_mock: true,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    })
}

#[cfg(not(feature = "mock-proofs"))]
fn generate_noir_proof(claim: &ClaimInput, _circuit_path: &Path) -> Result<ProofOutput> {
    let _ = (
        &claim.merkle_root,
        &claim.recipient,
        &claim.nullifier,
        &claim.merkle_proof,
        &claim.merkle_indices,
    );
    anyhow::bail!(
        "Real proof generation not yet implemented. Please use the 'mock-proofs' feature for development only."
    );
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(feature = "mock-proofs")]
    {
        eprintln!();
        eprintln!("WARNING: Mock proofs feature is enabled for development only!");
        eprintln!(
            "The generated proof is NOT cryptographically valid and should NOT be used in production."
        );
        eprintln!();
    }

    println!("Reading claim from {:?}...", cli.input);
    let claim_content = fs::read_to_string(&cli.input).context("Failed to read claim file")?;
    let claim: ClaimInput =
        serde_json::from_str(&claim_content).context("Failed to parse claim JSON")?;

    println!("Generating Noir proof...");
    let proof_output = generate_noir_proof(&claim, &cli.circuit)?;

    println!("Writing proof to {:?}...", cli.output);
    let json_output =
        serde_json::to_string_pretty(&proof_output).context("Failed to serialize proof")?;
    write_file_atomic(&cli.output, &json_output).context("Failed to write proof file")?;

    println!("\nProof generated successfully!");
    println!("Public inputs: {:?}", proof_output.public_inputs);

    Ok(())
}
