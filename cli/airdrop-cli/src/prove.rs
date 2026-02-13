use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use airdrop_cli::write_file_atomic;

#[derive(Parser)]
#[command(name = "prove")]
#[command(about = "Generate Noir proof from claim JSON", long_about = None)]
struct Cli {
    /// Input claim JSON file
    #[arg(short, long)]
    input: PathBuf,

    /// Private key (hex format, with or without 0x prefix)
    /// Alternatively, use "-" to read from stdin (more secure)
    /// Required for real proof generation; optional for mock proofs
    #[arg(short = 'k', long)]
    private_key: Option<String>,

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
    /// TODO: Required for real proof generation - the Merkle proof path
    merkle_proof: Vec<String>,
    /// TODO: Required for real proof generation - the Merkle proof indices
    merkle_indices: Vec<bool>,
    leaf_index: usize,
    claimer_address: String,
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

fn validate_hex_32_bytes(value: &str, name: &str) -> Result<[u8; 32]> {
    let cleaned = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if cleaned.len() != 64 {
        anyhow::bail!(
            "Invalid {} length: expected 64 hex chars, got {}",
            name,
            cleaned.len()
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(cleaned, &mut bytes)
        .with_context(|| format!("Invalid hex encoding for {}", name))?;
    Ok(bytes)
}

fn parse_private_key(key_str: &str) -> Result<[u8; 32]> {
    let cleaned = key_str.trim().strip_prefix("0x").unwrap_or(key_str.trim());
    if cleaned.is_empty() {
        anyhow::bail!("Private key is empty");
    }
    let mut key_bytes = hex::decode(cleaned).context("Invalid private key format")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid private key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(private_key)
}

#[cfg(feature = "mock-proofs")]
fn generate_noir_proof(
    claim: &ClaimInput,
    _private_key: &[u8; 32],
    circuit_path: &Path,
) -> Result<ProofOutput> {
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
fn generate_noir_proof(
    claim: &ClaimInput,
    _private_key: &[u8; 32],
    _circuit_path: &Path,
) -> Result<ProofOutput> {
    let _ = (
        &claim.merkle_root,
        &claim.recipient,
        &claim.nullifier,
        &claim.merkle_proof,
        &claim.merkle_indices,
        &claim.leaf_index,
        &claim.claimer_address,
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

    validate_hex_32_bytes(&claim.merkle_root, "merkle_root")?;
    validate_hex_32_bytes(&claim.nullifier, "nullifier")?;

    #[cfg(not(feature = "mock-proofs"))]
    let mut private_key_bytes: [u8; 32] = {
        let key_str = match cli.private_key {
            Some(ref k) if k == "-" => {
                let mut buffer = String::new();
                std::io::stdin()
                    .read_line(&mut buffer)
                    .context("Failed to read private key from stdin")?;
                let trimmed = buffer.trim().to_string();
                buffer.zeroize();
                trimmed
            }
            Some(k) => k,
            None => anyhow::bail!("Private key is required for real proof generation"),
        };
        parse_private_key(&key_str)?
    };

    #[cfg(feature = "mock-proofs")]
    let mut private_key_bytes: [u8; 32] = {
        if let Some(ref key_str) = cli.private_key {
            if key_str != "-" {
                let _ = parse_private_key(key_str)?;
            }
        }
        [0u8; 32]
    };

    println!("Generating Noir proof...");
    let proof_output = generate_noir_proof(&claim, &private_key_bytes, &cli.circuit)?;
    private_key_bytes.zeroize();

    println!("Writing proof to {:?}...", cli.output);
    let json_output =
        serde_json::to_string_pretty(&proof_output).context("Failed to serialize proof")?;
    write_file_atomic(&cli.output, &json_output).context("Failed to write proof file")?;

    println!("\nProof generated successfully!");
    println!("Public inputs: {:?}", proof_output.public_inputs);

    Ok(())
}
