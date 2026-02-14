#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use airdrop_cli::write_file_atomic;

#[derive(Parser, Debug)]
#[command(name = "prove")]
#[command(about = "Generate Noir proof from claim JSON", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Input claim JSON file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Private key (hex format, with or without 0x prefix)
    /// Alternatively, use "-" to read from stdin (more secure)
    /// Required for real proof generation; optional for mock proofs
    #[arg(short = 'k', long)]
    pub private_key: Option<String>,

    /// Noir circuit directory
    #[arg(short = 'c', long)]
    pub circuit: PathBuf,

    /// Output proof file
    #[arg(short, long)]
    pub output: PathBuf,
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
    #[allow(dead_code)]
    leaf_index: usize,
    #[allow(dead_code)]
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

#[inline]
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

#[inline]
fn validate_recipient_address(value: &str) -> Result<[u8; 20]> {
    let cleaned = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if cleaned.len() != 40 {
        anyhow::bail!(
            "Invalid recipient address length: expected 40 hex chars, got {}",
            cleaned.len()
        );
    }
    let mut bytes = [0u8; 20];
    hex::decode_to_slice(cleaned, &mut bytes)
        .context("Invalid hex encoding for recipient address")?;
    if bytes == [0u8; 20] {
        anyhow::bail!("Recipient address cannot be zero");
    }
    Ok(bytes)
}

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[inline]
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

    validate_private_key_range(&private_key)
        .context("Invalid private key: must be within secp256k1 curve order")?;

    Ok(private_key)
}

#[inline]
fn validate_private_key_range(key_bytes: &[u8; 32]) -> Result<()> {
    if key_bytes == &[0u8; 32] {
        anyhow::bail!("Private key cannot be zero");
    }

    for i in 0..32 {
        match key_bytes[i].cmp(&SECP256K1_ORDER[i]) {
            std::cmp::Ordering::Less => return Ok(()),
            std::cmp::Ordering::Greater => {
                anyhow::bail!("Private key must be less than secp256k1 curve order");
            }
            std::cmp::Ordering::Equal => continue,
        }
    }

    anyhow::bail!("Private key must be less than secp256k1 curve order");
}

#[cfg(feature = "mock-proofs")]
fn generate_noir_proof(
    claim: &ClaimInput,
    private_key: &[u8; 32],
    circuit_path: &Path,
) -> Result<ProofOutput> {
    #[cfg(not(debug_assertions))]
    anyhow::bail!("Mock proofs cannot be used in release builds");

    if private_key == &[0u8; 32] {
        anyhow::bail!("Mock proofs still require a valid private key for input validation");
    }

    if !circuit_path.exists() {
        anyhow::bail!("Circuit directory does not exist: {:?}", circuit_path);
    }

    let nargo_toml = circuit_path.join("Nargo.toml");
    if !nargo_toml.exists() {
        anyhow::bail!(
            "Circuit directory does not contain Nargo.toml: {:?}",
            circuit_path
        );
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
#[allow(unused_variables)]
fn generate_noir_proof(
    claim: &ClaimInput,
    private_key: &[u8; 32],
    circuit_path: &Path,
) -> Result<ProofOutput> {
    anyhow::bail!(
        "Real proof generation not yet implemented. Please use the 'mock-proofs' feature for development only."
    );
}

fn read_private_key(key_opt: Option<&String>) -> Result<[u8; 32]> {
    let key_str = match key_opt {
        Some(k) if k == "-" => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_line(&mut buffer)
                .context("Failed to read private key from stdin")?;
            let trimmed = buffer.trim().to_string();
            buffer.zeroize();
            trimmed
        }
        Some(k) => k.clone(),
        None => anyhow::bail!("Private key is required for proof generation"),
    };
    parse_private_key(&key_str)
}

pub fn run(cli: &Cli) -> Result<()> {
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
    validate_recipient_address(&claim.recipient)?;

    let mut private_key_bytes = read_private_key(cli.private_key.as_ref())?;

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

fn main() -> Result<()> {
    run(&Cli::parse())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hex_32_bytes_valid() {
        let input = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = validate_hex_32_bytes(input, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hex_32_bytes_valid_no_prefix() {
        let input = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = validate_hex_32_bytes(input, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hex_32_bytes_invalid_length() {
        let input = "0x1234";
        let result = validate_hex_32_bytes(input, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hex_32_bytes_invalid_hex() {
        let input = "0xghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890";
        let result = validate_hex_32_bytes(input, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hex_32_bytes_whitespace() {
        let input = "  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  ";
        let result = validate_hex_32_bytes(input, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_private_key_valid() {
        let key = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_private_key(key);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn test_parse_private_key_valid_no_prefix() {
        let key = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_private_key(key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_private_key_zero_rejected() {
        let key = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_private_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_private_key_exceeds_order_rejected() {
        let key = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let result = parse_private_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_private_key_just_below_order() {
        let key = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
        let result = parse_private_key(key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_private_key_empty() {
        let key = "";
        let result = parse_private_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_private_key_invalid_length() {
        let key = "0x1234";
        let result = parse_private_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_private_key_invalid_hex() {
        let key = "0xghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890";
        let result = parse_private_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_recipient_address_valid() {
        let addr = "0x1234567890abcdef1234567890abcdef12345678";
        let result = validate_recipient_address(addr);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 20);
    }

    #[test]
    fn test_validate_recipient_address_valid_no_prefix() {
        let addr = "1234567890abcdef1234567890abcdef12345678";
        let result = validate_recipient_address(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_recipient_address_invalid_length() {
        let addr = "0x1234";
        let result = validate_recipient_address(addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_recipient_address_zero() {
        let addr = "0x0000000000000000000000000000000000000000";
        let result = validate_recipient_address(addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_recipient_address_invalid_hex() {
        let addr = "0xghijklmnopqrstuvwxyz1234567890abcdef";
        let result = validate_recipient_address(addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_claim_input_deserialization() {
        let json = r#"{
            "merkle_root": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            "nullifier": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "merkle_proof": ["0x1111111111111111111111111111111111111111111111111111111111111111"],
            "merkle_indices": [true],
            "leaf_index": 0,
            "claimer_address": "0x1234567890abcdef1234567890abcdef12345678"
        }"#;
        let claim: ClaimInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            claim.merkle_root,
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(claim.leaf_index, 0);
    }

    #[test]
    #[cfg(feature = "mock-proofs")]
    fn test_generate_mock_proof() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        file.write_all(b"[package]\nname = \"test\"\n").unwrap();
        drop(file);

        let claim = ClaimInput {
            merkle_root: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            merkle_proof: vec![],
            merkle_indices: vec![],
            leaf_index: 0,
            claimer_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        };
        let private_key = [1u8; 32];
        let result = generate_noir_proof(&claim, &private_key, temp_dir.path());
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert!(proof.is_mock);
        assert_eq!(proof.public_inputs.len(), 3);
    }

    #[test]
    #[cfg(feature = "mock-proofs")]
    fn test_generate_mock_proof_rejects_zero_key() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        file.write_all(b"[package]\nname = \"test\"\n").unwrap();
        drop(file);

        let claim = ClaimInput {
            merkle_root: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            merkle_proof: vec![],
            merkle_indices: vec![],
            leaf_index: 0,
            claimer_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        };
        let private_key = [0u8; 32];
        let result = generate_noir_proof(&claim, &private_key, temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "mock-proofs")]
    fn test_generate_mock_proof_requires_nargo_toml() {
        let temp_dir = tempfile::tempdir().unwrap();

        let claim = ClaimInput {
            merkle_root: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            merkle_proof: vec![],
            merkle_indices: vec![],
            leaf_index: 0,
            claimer_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        };
        let private_key = [1u8; 32];
        let result = generate_noir_proof(&claim, &private_key, temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nargo.toml"));
    }
}
