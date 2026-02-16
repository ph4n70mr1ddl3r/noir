#![forbid(unsafe_code)]

#[cfg(all(feature = "mock-proofs", not(debug_assertions)))]
compile_error!("Mock proofs cannot be enabled in release builds");

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use airdrop_cli::{
    is_path_safe, validate_private_key_range, write_file_atomic, MERKLE_DEPTH,
    SECP256K1_HALF_ORDER_BE,
};

const MAX_CLAIM_FILE_SIZE: u64 = 10 * 1024 * 1024;
const SIGNATURE_LENGTH: usize = 64;
const PUBLIC_KEY_COORD_LENGTH: usize = 32;
const EXPECTED_CIRCUIT_VERSION: &str = "0.1.0";

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
    /// Optional: if not provided, uses private_key_le_bytes from claim JSON
    /// If provided, validates it matches the key in claim JSON
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
    private_key_le_bytes: Option<String>,
    #[allow(dead_code)]
    public_key_x: String,
    #[allow(dead_code)]
    public_key_y: String,
    #[allow(dead_code)]
    signature: String,
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

#[inline]
fn validate_signature(value: &str) -> Result<[u8; 64]> {
    let cleaned = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if cleaned.len() != SIGNATURE_LENGTH * 2 {
        anyhow::bail!(
            "Invalid signature length: expected {} hex chars, got {}",
            SIGNATURE_LENGTH * 2,
            cleaned.len()
        );
    }
    let mut bytes = [0u8; 64];
    hex::decode_to_slice(cleaned, &mut bytes).context("Invalid hex encoding for signature")?;

    // Check that r (first 32 bytes) is non-zero
    let r_nonzero = bytes[..32].iter().any(|&b| b != 0);
    if !r_nonzero {
        anyhow::bail!("Invalid signature: r component is zero");
    }

    // Check that s (second 32 bytes) is non-zero
    let s_nonzero = bytes[32..64].iter().any(|&b| b != 0);
    if !s_nonzero {
        anyhow::bail!("Invalid signature: s component is zero");
    }

    // Check that s is in lower half of curve order (low-s requirement)
    // Standard requires s <= n/2, so we check for s > n/2 (strictly greater)
    let mut s_greater = false;
    let mut all_equal = true;
    for i in 0..32 {
        if all_equal {
            match bytes[32 + i].cmp(&SECP256K1_HALF_ORDER_BE[i]) {
                std::cmp::Ordering::Greater => {
                    s_greater = true;
                    all_equal = false;
                }
                std::cmp::Ordering::Less => all_equal = false,
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    // s == n/2 is valid (boundary case), only reject if s > n/2
    if s_greater {
        anyhow::bail!("Invalid signature: s component exceeds half order (not low-s)");
    }

    Ok(bytes)
}

#[inline]
fn validate_public_key_coord(value: &str, name: &str) -> Result<[u8; 32]> {
    let cleaned = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if cleaned.len() != PUBLIC_KEY_COORD_LENGTH * 2 {
        anyhow::bail!(
            "Invalid {} length: expected {} hex chars, got {}",
            name,
            PUBLIC_KEY_COORD_LENGTH * 2,
            cleaned.len()
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(cleaned, &mut bytes)
        .with_context(|| format!("Invalid hex encoding for {}", name))?;

    // Validate that the public key coordinate is not all zeros
    if bytes == [0u8; 32] {
        anyhow::bail!("Invalid {}: cannot be all zeros", name);
    }

    Ok(bytes)
}

#[inline]
fn validate_merkle_proof_element(value: &str, index: usize) -> Result<[u8; 32]> {
    let cleaned = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if cleaned.len() != 64 {
        anyhow::bail!(
            "Invalid merkle_proof[{}] length: expected 64 hex chars, got {}",
            index,
            cleaned.len()
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(cleaned, &mut bytes)
        .with_context(|| format!("Invalid hex encoding for merkle_proof[{}]", index))?;
    Ok(bytes)
}

fn verify_circuit_version(circuit_path: &Path) -> Result<()> {
    let nargo_toml_path = circuit_path.join("Nargo.toml");
    if !nargo_toml_path.exists() {
        anyhow::bail!(
            "Circuit directory does not contain Nargo.toml: {:?}",
            circuit_path
        );
    }

    let nargo_content =
        fs::read_to_string(&nargo_toml_path).context("Failed to read Nargo.toml")?;

    let mut in_package_section = false;

    for line in nargo_content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed == "[package]" {
            in_package_section = true;
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_package_section = trimmed == "[package]";
            continue;
        }

        if in_package_section && trimmed.starts_with("version") {
            if let Some(eq_pos) = trimmed.find('=') {
                let version = trimmed[eq_pos + 1..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');

                if version != EXPECTED_CIRCUIT_VERSION {
                    anyhow::bail!(
                        "Circuit version mismatch: expected '{}', found '{}'. \
                         Please update CLI or circuit to match versions.",
                        EXPECTED_CIRCUIT_VERSION,
                        version
                    );
                }
                return Ok(());
            }
        }
    }

    eprintln!(
        "WARNING: No version field found in Nargo.toml [package] section. Expected version '{}'. Proceeding anyway, but circuit compatibility cannot be verified.",
        EXPECTED_CIRCUIT_VERSION
    );
    Ok(())
}

#[inline]
fn parse_private_key(key_str: &str) -> Result<[u8; 32]> {
    let cleaned = key_str.trim().strip_prefix("0x").unwrap_or(key_str.trim());
    if cleaned.is_empty() {
        anyhow::bail!("Private key is empty");
    }
    let mut key_bytes = hex::decode(cleaned).context("Invalid private key format")?;
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        anyhow::bail!(
            "Invalid private key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();

    if let Err(e) = validate_private_key_range(&private_key) {
        private_key.zeroize();
        return Err(e).context("Invalid private key: must be within secp256k1 curve order");
    }

    Ok(private_key)
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
    let _ = (claim, private_key, circuit_path);
    anyhow::bail!(
        "Real proof generation not implemented.\n\
         \n\
         For development/testing, use the 'mock-proofs' feature:\n\
           cargo run --features mock-proofs -- prove ...\n\
         \n\
         WARNING: Mock proofs are NOT cryptographically valid and will be\n\
         rejected by the on-chain verifier.\n\
         \n\
         To generate real proofs, you must integrate with the Noir proving\n\
         system (nargo backend or Barretenberg). See the Noir documentation:\n\
         https://noir-lang.org/docs/"
    );
}

fn read_private_key(key_opt: Option<&String>) -> Result<[u8; 32]> {
    let mut key_str = match key_opt {
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
    let result = parse_private_key(&key_str);
    key_str.zeroize();
    result
}

fn parse_private_key_le_from_claim(claim: &ClaimInput) -> Result<Option<[u8; 32]>> {
    let Some(key_str) = &claim.private_key_le_bytes else {
        return Ok(None);
    };

    let cleaned = key_str.trim().strip_prefix("0x").unwrap_or(key_str.trim());
    if cleaned.is_empty() {
        anyhow::bail!("private_key_le_bytes in claim JSON is empty");
    }
    let mut key_bytes =
        hex::decode(cleaned).context("Invalid private_key_le_bytes format in claim JSON")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid private_key_le_bytes length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();

    let mut be_key = private_key;
    be_key.reverse();
    if let Err(e) = validate_private_key_range(&be_key) {
        private_key.zeroize();
        be_key.zeroize();
        return Err(e).context(
            "Invalid private_key_le_bytes in claim JSON: must be within secp256k1 curve order",
        );
    }

    Ok(Some(private_key))
}

fn validate_keys_match(cli_key: &[u8; 32], claim_key_le: &[u8; 32]) -> Result<()> {
    let mut cli_key_le = *cli_key;
    cli_key_le.reverse();

    if cli_key_le != *claim_key_le {
        cli_key_le.zeroize();
        anyhow::bail!(
            "Private key provided via CLI does not match private_key_le_bytes in claim JSON"
        );
    }
    cli_key_le.zeroize();
    Ok(())
}

pub fn run(cli: &Cli) -> Result<()> {
    if !is_path_safe(&cli.input) {
        anyhow::bail!("Invalid input path: directory traversal not allowed");
    }
    if !is_path_safe(&cli.circuit) {
        anyhow::bail!("Invalid circuit path: directory traversal not allowed");
    }
    if !is_path_safe(&cli.output) {
        anyhow::bail!("Invalid output path: directory traversal not allowed");
    }

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
    let metadata = fs::metadata(&cli.input).context("Failed to read claim file metadata")?;
    if metadata.len() > MAX_CLAIM_FILE_SIZE {
        anyhow::bail!(
            "Claim file too large: {} bytes (max {} bytes)",
            metadata.len(),
            MAX_CLAIM_FILE_SIZE
        );
    }
    let claim_content = fs::read_to_string(&cli.input).context("Failed to read claim file")?;
    let claim: ClaimInput =
        serde_json::from_str(&claim_content).context("Failed to parse claim JSON")?;

    validate_hex_32_bytes(&claim.merkle_root, "merkle_root")?;
    validate_hex_32_bytes(&claim.nullifier, "nullifier")?;
    validate_recipient_address(&claim.recipient)?;
    validate_signature(&claim.signature)?;
    validate_public_key_coord(&claim.public_key_x, "public_key_x")?;
    validate_public_key_coord(&claim.public_key_y, "public_key_y")?;

    if claim.merkle_proof.len() != MERKLE_DEPTH {
        anyhow::bail!(
            "Invalid merkle_proof length: expected {}, got {}",
            MERKLE_DEPTH,
            claim.merkle_proof.len()
        );
    }
    for (i, proof_elem) in claim.merkle_proof.iter().enumerate() {
        validate_merkle_proof_element(proof_elem, i)?;
    }

    if claim.merkle_indices.len() != MERKLE_DEPTH {
        anyhow::bail!(
            "Invalid merkle_indices length: expected {}, got {}",
            MERKLE_DEPTH,
            claim.merkle_indices.len()
        );
    }

    let claim_key_le_bytes = parse_private_key_le_from_claim(&claim)?;
    let mut private_key_le_bytes: [u8; 32] = match (&claim_key_le_bytes, &cli.private_key) {
        (Some(claim_key), Some(cli_key)) => {
            println!("Validating private key matches claim JSON...");
            let mut cli_key_bytes = read_private_key(Some(cli_key))?;
            validate_keys_match(&cli_key_bytes, claim_key)?;
            cli_key_bytes.zeroize();
            *claim_key
        }
        (Some(claim_key), None) => {
            println!("Using private_key_le_bytes from claim JSON...");
            *claim_key
        }
        (None, Some(cli_key)) => {
            println!("Converting CLI private key to little-endian format...");
            let mut cli_key_bytes = read_private_key(Some(cli_key))?;
            cli_key_bytes.reverse();
            cli_key_bytes
        }
        (None, None) => {
            anyhow::bail!(
                "Private key required but not available.\n\
                 The claim JSON does not contain private_key_le_bytes (--exclude-private-key was used).\n\
                 Please provide the private key via --private-key flag or stdin."
            );
        }
    };

    println!("Verifying circuit version...");
    verify_circuit_version(&cli.circuit).context("Circuit version verification failed")?;

    println!("Generating Noir proof...");
    let proof_output = generate_noir_proof(&claim, &private_key_le_bytes, &cli.circuit)?;
    private_key_le_bytes.zeroize();

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
            "claimer_address": "0x1234567890abcdef1234567890abcdef12345678",
            "private_key_le_bytes": "0x0100000000000000000000000000000000000000000000000000000000000000",
            "public_key_x": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "public_key_y": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "signature": "0x4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"
        }"#;
        let claim: ClaimInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            claim.merkle_root,
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(claim.leaf_index, 0);
    }

    #[test]
    fn test_validate_claim_input_merkle_proof_length() {
        let claim = ClaimInput {
            merkle_root: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            merkle_proof: vec!["0x1111111111111111111111111111111111111111111111111111111111111111".to_string()],
            merkle_indices: vec![],
            leaf_index: 0,
            claimer_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            private_key_le_bytes: Some("0x0100000000000000000000000000000000000000000000000000000000000000".to_string()),
            public_key_x: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            public_key_y: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            signature: "0x4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444".to_string(),
        };
        assert_ne!(claim.merkle_proof.len(), MERKLE_DEPTH);
    }

    #[test]
    fn test_validate_claim_input_merkle_indices_length() {
        let claim = ClaimInput {
            merkle_root: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            merkle_proof: vec![],
            merkle_indices: vec![true],
            leaf_index: 0,
            claimer_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            private_key_le_bytes: Some("0x0100000000000000000000000000000000000000000000000000000000000000".to_string()),
            public_key_x: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            public_key_y: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            signature: "0x4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444".to_string(),
        };
        assert_ne!(claim.merkle_indices.len(), MERKLE_DEPTH);
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
            private_key_le_bytes: Some("0x0100000000000000000000000000000000000000000000000000000000000000".to_string()),
            public_key_x: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            public_key_y: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            signature: "0x4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444".to_string(),
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
            private_key_le_bytes: Some("0x0100000000000000000000000000000000000000000000000000000000000000".to_string()),
            public_key_x: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            public_key_y: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            signature: "0x4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444".to_string(),
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
            private_key_le_bytes: Some("0x0100000000000000000000000000000000000000000000000000000000000000".to_string()),
            public_key_x: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            public_key_y: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            signature: "0x4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444".to_string(),
        };
        let private_key = [1u8; 32];
        let result = generate_noir_proof(&claim, &private_key, temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nargo.toml"));
    }

    #[test]
    fn test_validate_signature_valid() {
        let sig = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = validate_signature(sig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_s_equals_half_order_is_valid() {
        // s = n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        // This is the boundary case and should be VALID (s <= n/2)
        let sig = "0x00000000000000000000000000000000000000000000000000000000000000017FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";
        let result = validate_signature(sig);
        assert!(result.is_ok(), "s == n/2 should be valid");
    }

    #[test]
    fn test_validate_signature_s_exceeds_half_order() {
        // s = n/2 + 1 (exceeds half order, should be rejected)
        let sig = "0x00000000000000000000000000000000000000000000000000000000000000017FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
        let result = validate_signature(sig);
        assert!(result.is_err(), "s > n/2 should be rejected");
    }

    #[test]
    fn test_validate_signature_invalid_length() {
        let sig = "0x1234";
        let result = validate_signature(sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_public_key_coord_valid() {
        let coord = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = validate_public_key_coord(coord, "test_coord");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_public_key_coord_invalid_length() {
        let coord = "0x1234";
        let result = validate_public_key_coord(coord, "test_coord");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_merkle_proof_element_valid() {
        let elem = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = validate_merkle_proof_element(elem, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_merkle_proof_element_invalid_length() {
        let elem = "0x1234";
        let result = validate_merkle_proof_element(elem, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("merkle_proof[0]"));
    }

    #[test]
    fn test_validate_merkle_proof_element_invalid_hex() {
        let elem = "0xghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890abcd";
        let result = validate_merkle_proof_element(elem, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("merkle_proof[5]"));
    }

    #[test]
    fn test_verify_circuit_version_valid() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        writeln!(file, "[package]\nname = \"test\"\nversion = \"0.1.0\"").unwrap();
        drop(file);

        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_circuit_version_mismatch() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        writeln!(file, "[package]\nname = \"test\"\nversion = \"0.2.0\"").unwrap();
        drop(file);

        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version mismatch"));
    }

    #[test]
    fn test_verify_circuit_version_missing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nargo.toml"));
    }

    #[test]
    fn test_verify_circuit_version_missing_version_field() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        writeln!(file, "[package]\nname = \"test\"").unwrap();
        drop(file);

        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_circuit_version_ignores_other_sections() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        writeln!(
            file,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n[dependencies]\nversion = \"wrong\""
        )
        .unwrap();
        drop(file);

        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_circuit_version_handles_comments() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        writeln!(
            file,
            "# Comment\n[package]\n# Another comment\nname = \"test\"\nversion = \"0.1.0\""
        )
        .unwrap();
        drop(file);

        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_circuit_version_single_quotes() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let nargo_path = temp_dir.path().join("Nargo.toml");
        let mut file = std::fs::File::create(&nargo_path).unwrap();
        writeln!(file, "[package]\nname = \"test\"\nversion = '0.1.0'").unwrap();
        drop(file);

        let result = verify_circuit_version(temp_dir.path());
        assert!(result.is_ok());
    }
}
