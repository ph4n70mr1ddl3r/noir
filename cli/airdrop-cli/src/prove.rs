use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

// TODO: Replace mock proof generation with actual Noir proof generation
// using the Noir SDK or calling nargo programmatically
//
// WARNING: This function currently returns mock/hardcoded values and is NOT suitable for production use.
// The actual proof must be generated using the Noir circuit. For proper integration:
// 1. Compile the Noir circuit using nargo
// 2. Generate the proof with the claim inputs
// 3. Return the actual proof bytes and verified public inputs
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
#[allow(dead_code)]
struct ClaimInput {
    merkle_root: String,
    recipient: String,
    nullifier: String,
    merkle_proof: Vec<String>,
    private_key_field: String,
}

#[derive(Debug, Serialize)]
struct ProofOutput {
    proof: Vec<String>,
    public_inputs: Vec<String>,
}

// WARNING: This is a MOCK implementation that returns hardcoded values.
// Do NOT use in production. Replace with actual Noir proof generation.
fn generate_noir_proof(claim: &ClaimInput, circuit_path: &Path) -> Result<ProofOutput> {
    if !circuit_path.exists() {
        anyhow::bail!("Circuit directory does not exist: {:?}", circuit_path);
    }

    let _prover_path = circuit_path.join("target").join("airdrop.json");

    let public_inputs = vec![
        claim.merkle_root.clone(),
        claim.recipient.clone(),
        claim.nullifier.clone(),
    ];

    let proof = vec!["0x1".to_string(), "0x2".to_string()];

    Ok(ProofOutput {
        proof,
        public_inputs,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("Reading claim from {:?}...", cli.input);
    let claim_content = fs::read_to_string(&cli.input).context("Failed to read claim file")?;
    let claim: ClaimInput =
        serde_json::from_str(&claim_content).context("Failed to parse claim JSON")?;

    eprintln!();
    eprintln!("WARNING: This is a MOCK proof implementation for development only!");
    eprintln!(
        "The generated proof is NOT cryptographically valid and should NOT be used in production."
    );
    eprintln!("Replace with actual Noir proof generation before deployment.");
    eprintln!();

    println!("Generating Noir proof...");
    let proof_output = generate_noir_proof(&claim, &cli.circuit)?;

    println!("Writing proof to {:?}...", cli.output);
    let json_output =
        serde_json::to_string_pretty(&proof_output).context("Failed to serialize proof")?;
    let temp_path = cli.output.with_extension("tmp");
    let mut file = File::create(&temp_path).context("Failed to create temp file")?;
    file.write_all(json_output.as_bytes())
        .context("Failed to write to temp file")?;
    file.flush().context("Failed to flush temp file")?;
    std::fs::rename(&temp_path, &cli.output).context("Failed to move temp file to output")?;

    println!("\nProof generated successfully!");
    println!("Public inputs: {:?}", proof_output.public_inputs);

    Ok(())
}
