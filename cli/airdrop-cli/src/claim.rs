#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use k256::ecdsa::SigningKey;
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use airdrop_cli::{
    get_merkle_proof, hex_encode, keccak256_hash, parse_address, validate_merkle_root,
    validate_private_key_range, write_file_atomic, DOMAIN_SEPARATOR_BYTES, MERKLE_DEPTH,
};

use k256::ecdsa::signature::Signer;

#[derive(Parser, Debug)]
#[command(name = "claim")]
#[command(about = "Generate airdrop claim proof", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Path to Merkle tree file
    #[arg(short = 't', long)]
    pub tree: PathBuf,

    /// Path to index map file
    #[arg(short = 'i', long)]
    pub index_map: PathBuf,

    /// Private key (hex format, with or without 0x prefix)
    /// Alternatively, use "-" to read from stdin (more secure)
    #[arg(short = 'k', long)]
    pub private_key: String,

    /// Recipient address (where to receive tokens)
    #[arg(short = 'r', long)]
    pub recipient: String,

    /// Output JSON file
    #[arg(short, long)]
    pub output: PathBuf,

    /// Merkle root (hex format)
    #[arg(short, long)]
    pub root: String,
}

#[derive(Debug, Serialize)]
struct ClaimOutput {
    merkle_root: String,
    recipient: String,
    nullifier: String,
    merkle_proof: Vec<String>,
    merkle_indices: Vec<bool>,
    leaf_index: usize,
    claimer_address: String,
    private_key_le_bytes: String,
    public_key_x: String,
    public_key_y: String,
    signature: String,
}

/// Computes a nullifier from a private key to prevent double-claiming.
///
/// Uses Keccak256 with a domain separator for cryptographic strength.
/// The private key is converted to little-endian to match Noir's `to_le_bytes()`.
///
/// # Arguments
/// * `private_key_bytes` - 32-byte private key (big-endian format as typical for Ethereum)
///
/// # Returns
/// 32-byte nullifier hash
pub fn compute_nullifier(private_key_bytes: &[u8; 32]) -> Result<[u8; 32]> {
    let mut domain_padded = [0u8; 32];
    domain_padded[28..32].copy_from_slice(&DOMAIN_SEPARATOR_BYTES);
    let mut le_key = *private_key_bytes;
    le_key.reverse();
    let mut hasher = Keccak256::new();
    hasher.update(le_key);
    hasher.update(domain_padded);
    let result = hasher.finalize();
    Ok(result.into())
}

/// Loads the index map from a file.
///
/// The file format is: `0xADDRESS:INDEX` per line.
///
/// # Arguments
/// * `path` - Path to the index map file
///
/// # Returns
/// A HashMap mapping 20-byte addresses to their leaf indices
///
/// # Errors
/// Returns an error if the file doesn't exist, is empty, or has invalid format
fn load_index_map(path: &Path) -> Result<HashMap<[u8; 20], usize>> {
    if !path.exists() {
        anyhow::bail!("Index map file does not exist: {:?}", path);
    }
    let file = File::open(path).context("Failed to open index map file")?;
    let metadata = file.metadata().context("Failed to get file metadata")?;
    let estimated_entries = (metadata.len() as usize / 64).max(16);
    let reader = BufReader::new(file);
    let mut map = HashMap::with_capacity(estimated_entries);

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid format at line {}: expected 'address:index', got '{}'",
                line_num + 1,
                trimmed
            );
        }
        let address = parse_address(parts[0]).context("Invalid address format")?;
        let index: usize = parts[1].parse().context("Invalid index format")?;
        map.insert(address, index);
    }

    if map.is_empty() {
        anyhow::bail!("Index map file is empty");
    }

    Ok(map)
}

const MAX_TREE_SIZE: usize = 100_000_000;

/// Loads and validates a Merkle tree from a file.
///
/// The file format is: `LEVEL:INDEX:0xHASH` per line.
/// Validates tree integrity by recomputing parent hashes.
///
/// # Arguments
/// * `path` - Path to the Merkle tree file
///
/// # Returns
/// A vector of levels, where each level is a vector of 32-byte hashes
///
/// # Errors
/// Returns an error if the file doesn't exist, is empty, has invalid format,
/// or fails tree integrity validation
fn load_merkle_tree(path: &Path) -> Result<Vec<Vec<[u8; 32]>>> {
    if !path.exists() {
        anyhow::bail!("Merkle tree file does not exist: {:?}", path);
    }
    let file = File::open(path).context("Failed to open Merkle tree file")?;
    let reader = BufReader::new(file);

    let mut level_entries: Vec<HashMap<usize, [u8; 32]>> = Vec::new();

    for line in reader.lines() {
        let line = line.context("Failed to read line")?;
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let level: usize = parts[0].parse().context("Invalid level format")?;
            let index: usize = parts[1].parse().context("Invalid index format")?;
            if index > MAX_TREE_SIZE {
                anyhow::bail!(
                    "Tree index {} exceeds maximum allowed {}",
                    index,
                    MAX_TREE_SIZE
                );
            }
            let hash_str = if parts[2].starts_with("0x") {
                &parts[2][2..]
            } else {
                parts[2]
            };
            let mut hash = [0u8; 32];
            hex::decode_to_slice(hash_str, &mut hash).context("Invalid hash format")?;

            if level >= level_entries.len() {
                level_entries.push(HashMap::new());
            }
            if level_entries[level].contains_key(&index) {
                anyhow::bail!("Duplicate entry at level {}, index {}", level, index);
            }
            level_entries[level].insert(index, hash);
        }
    }

    if level_entries.is_empty() {
        anyhow::bail!("Merkle tree file is empty");
    }

    let mut tree: Vec<Vec<[u8; 32]>> = Vec::new();
    for (level_num, level_map) in level_entries.iter().enumerate() {
        if level_map.is_empty() {
            anyhow::bail!("Level {} is empty", level_num);
        }
        let max_index = level_map.keys().max().unwrap_or(&0);
        let expected_len = max_index + 1;
        if level_map.len() != expected_len {
            anyhow::bail!(
                "Non-contiguous indices at level {}: expected {} entries (0..={}), found {}. Tree indices must be contiguous starting from 0.",
                level_num,
                expected_len,
                max_index,
                level_map.len()
            );
        }
        let mut level = vec![[0u8; 32]; max_index + 1];
        for (&idx, &hash) in level_map {
            level[idx] = hash;
        }

        if level_num > 0 {
            let expected_parent_count = tree[level_num - 1].len().div_ceil(2);
            if level.len() != expected_parent_count {
                anyhow::bail!(
                    "Invalid tree structure: level {} has {} nodes but expected {} based on level {}",
                    level_num,
                    level.len(),
                    expected_parent_count,
                    level_num - 1
                );
            }
        }

        tree.push(level);
    }

    if tree.last().map(|l| l.len()) != Some(1) {
        anyhow::bail!(
            "Invalid tree structure: root level must have exactly 1 node, found {}",
            tree.last().map(|l| l.len()).unwrap_or(0)
        );
    }

    for level_num in 1..tree.len() {
        for i in 0..tree[level_num].len() {
            let left_idx = i * 2;
            let right_idx = left_idx + 1;
            let left = tree[level_num - 1][left_idx];
            let right = if right_idx < tree[level_num - 1].len() {
                tree[level_num - 1][right_idx]
            } else {
                left
            };
            let expected = keccak256_hash(left, right);
            if tree[level_num][i] != expected {
                anyhow::bail!(
                    "Tree integrity check failed at level {} index {}: hash mismatch",
                    level_num,
                    i
                );
            }
        }
    }

    Ok(tree)
}

/// Derives an Ethereum address from an ECDSA signing key.
///
/// Uses standard Ethereum address derivation: last 20 bytes of Keccak256(uncompressed public key).
///
/// # Arguments
/// * `signing_key` - The secp256k1 signing key
///
/// # Returns
/// 20-byte Ethereum address
#[inline]
fn private_key_to_address(signing_key: &SigningKey) -> ([u8; 20], [u8; 32], [u8; 32]) {
    let public_key = signing_key.verifying_key();
    let encoded = public_key.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();

    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pub_bytes[1..33]);
    pub_key_y.copy_from_slice(&pub_bytes[33..65]);

    let hash = Keccak256::digest(&pub_bytes[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    (address, pub_key_x, pub_key_y)
}

pub fn run(mut cli: Cli) -> Result<()> {
    println!("Validating Merkle root...");
    let merkle_root = validate_merkle_root(&cli.root).context("Invalid Merkle root")?;

    println!("Loading Merkle tree...");
    let tree = load_merkle_tree(&cli.tree).context("Failed to load Merkle tree")?;

    let tree_root = tree
        .last()
        .and_then(|level| level.first())
        .copied()
        .context("Invalid tree structure: no root found")?;
    if tree_root != merkle_root {
        anyhow::bail!(
            "Merkle root mismatch: tree root {} does not match provided root {}",
            hex_encode(tree_root),
            hex_encode(merkle_root)
        );
    }

    println!("Loading index map...");
    let index_map = load_index_map(&cli.index_map).context("Failed to load index map")?;

    println!("Parsing private key...");
    let mut key_str = if cli.private_key == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_line(&mut buffer)
            .context("Failed to read private key from stdin")?;
        let trimmed = buffer.trim().to_string();
        buffer.zeroize();
        trimmed
    } else {
        std::mem::take(&mut cli.private_key)
    };
    let key_str_ref = key_str.strip_prefix("0x").unwrap_or(&key_str);
    if key_str_ref.is_empty() {
        key_str.zeroize();
        anyhow::bail!("Private key is empty");
    }
    let mut key_bytes = hex::decode(key_str_ref).context("Invalid private key format")?;
    key_str.zeroize();
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        anyhow::bail!(
            "Invalid private key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(&key_bytes);
    key_bytes.zeroize();

    validate_private_key_range(&private_key_bytes)
        .context("Invalid private key: must be within secp256k1 curve order")?;

    let signing_key = SigningKey::from_slice(&private_key_bytes).context("Invalid private key")?;

    println!("Deriving address from private key...");
    let (claimer_address, public_key_x, public_key_y) = private_key_to_address(&signing_key);

    println!("Computing nullifier...");
    let nullifier = compute_nullifier(&private_key_bytes)?;

    let mut private_key_le_bytes = private_key_bytes;
    private_key_le_bytes.reverse();

    println!("Signing claimer address...");
    let mut message: [u8; 32] = [0u8; 32];
    message[12..32].copy_from_slice(&claimer_address);
    let message_hash = Keccak256::digest(message);
    let signature: k256::ecdsa::Signature = signing_key.sign(&message_hash);
    let sig_bytes = signature.to_bytes();
    let mut signature_bytes: [u8; 64] = [0u8; 64];
    signature_bytes.copy_from_slice(&sig_bytes);

    private_key_bytes.zeroize();

    println!("Looking up address in index map...");
    let leaf_index = index_map
        .get(&claimer_address)
        .copied()
        .context("Address not found in qualified list")?;
    let tree_size = tree.first().map(|l| l.len()).unwrap_or(0);
    if leaf_index >= tree_size {
        anyhow::bail!(
            "Leaf index {} is out of bounds for tree with {} leaves",
            leaf_index,
            tree_size
        );
    }

    println!("Generating Merkle proof...");
    let (merkle_proof, merkle_indices) =
        get_merkle_proof(&tree, leaf_index).context("Failed to generate Merkle proof")?;

    if merkle_proof.is_empty() && !tree.is_empty() && tree[0].len() > 1 {
        anyhow::bail!("Invalid Merkle proof: proof is empty but tree has multiple leaves");
    }

    if merkle_proof.len() != MERKLE_DEPTH {
        anyhow::bail!(
            "Internal error: proof length ({}) does not match MERKLE_DEPTH ({})",
            merkle_proof.len(),
            MERKLE_DEPTH
        );
    }

    println!("Parsing recipient address...");
    let recipient = parse_address(&cli.recipient).context("Invalid recipient address")?;

    if recipient != claimer_address {
        eprintln!(
            "WARNING: Recipient address ({}) differs from claimer address ({}). Tokens will be sent to the recipient, not to the address derived from your private key.",
            hex_encode(recipient),
            hex_encode(claimer_address)
        );
    }

    let claim = ClaimOutput {
        merkle_root: hex_encode(merkle_root),
        recipient: hex_encode(recipient),
        nullifier: hex_encode(nullifier),
        merkle_proof: merkle_proof.iter().copied().map(hex_encode).collect(),
        merkle_indices,
        leaf_index,
        claimer_address: hex_encode(claimer_address),
        private_key_le_bytes: hex_encode(private_key_le_bytes),
        public_key_x: hex_encode(public_key_x),
        public_key_y: hex_encode(public_key_y),
        signature: hex_encode(signature_bytes),
    };

    private_key_le_bytes.zeroize();

    if cli.output.exists() {
        eprintln!(
            "WARNING: Output file {:?} already exists and will be overwritten.",
            cli.output
        );
    }

    println!("Writing claim JSON to {:?}...", cli.output);
    let json_output = serde_json::to_string_pretty(&claim).context("Failed to serialize JSON")?;
    write_file_atomic(&cli.output, &json_output).context("Failed to write claim file")?;

    eprintln!();
    eprintln!("SECURITY WARNING: The output file contains sensitive data including:");
    eprintln!("  - Your private key (in little-endian format, derived from your original key)");
    eprintln!("  - Your signature");
    eprintln!("  - Your nullifier");
    eprintln!("Store this file securely and delete it after use. Anyone with access to");
    eprintln!("this file can potentially compromise your account.");
    eprintln!();
    eprintln!("NOTE: Private keys have been zeroized from memory after use.");

    println!("\nClaim generated successfully!");
    println!("Claimer address: {}", hex_encode(claimer_address));
    println!("Recipient: {}", hex_encode(recipient));
    println!("Nullifier: {}", hex_encode(nullifier));
    println!("Proof length: {} nodes", merkle_proof.len());
    Ok(())
}

fn main() -> Result<()> {
    run(Cli::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use airdrop_cli::SECP256K1_ORDER;

    #[test]
    fn test_compute_nullifier_deterministic() {
        let key = [1u8; 32];
        let nullifier1 = compute_nullifier(&key).unwrap();
        let nullifier2 = compute_nullifier(&key).unwrap();
        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_compute_nullifier_different_keys() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nullifier1 = compute_nullifier(&key1).unwrap();
        let nullifier2 = compute_nullifier(&key2).unwrap();
        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_compute_nullifier_known_value() {
        let key = [0x11u8; 32];
        let nullifier = compute_nullifier(&key).unwrap();
        let expected: [u8; 32] = [
            0x98, 0x05, 0x1f, 0x98, 0xf8, 0xff, 0xc5, 0xe2, 0xc6, 0xac, 0x01, 0x5b, 0x6f, 0x18,
            0xec, 0x6f, 0x37, 0xd3, 0x6d, 0x55, 0x0d, 0x8e, 0xef, 0x8e, 0xad, 0xfc, 0xc7, 0x52,
            0x9a, 0x56, 0x37, 0xfc,
        ];
        assert_eq!(nullifier, expected);
    }

    #[test]
    fn test_compute_nullifier_uses_little_endian() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let nullifier = compute_nullifier(&key).unwrap();

        let mut hasher = Keccak256::new();
        let mut le_key = key;
        le_key.reverse();
        hasher.update(le_key);
        let mut domain_padded = [0u8; 32];
        domain_padded[28..32].copy_from_slice(&DOMAIN_SEPARATOR_BYTES);
        hasher.update(domain_padded);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(nullifier, expected);
    }

    #[test]
    fn test_private_key_to_address() {
        let key_bytes = [1u8; 32];
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
        let (address, pub_x, pub_y) = private_key_to_address(&signing_key);
        assert_eq!(address.len(), 20);
        assert_ne!(address, [0u8; 20]);
        assert_eq!(pub_x.len(), 32);
        assert_eq!(pub_y.len(), 32);
    }

    #[test]
    fn test_private_key_to_address_known_vector() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
        let (address, _, _) = private_key_to_address(&signing_key);
        let expected: [u8; 20] = [
            0x7E, 0x5F, 0x45, 0x52, 0x09, 0x1A, 0x69, 0x12, 0x5D, 0x5D, 0xFC, 0xB7, 0xB8, 0xC2,
            0x65, 0x90, 0x29, 0x39, 0x5B, 0xDF,
        ];
        assert_eq!(address, expected);
    }

    #[test]
    fn test_private_key_to_address_deterministic() {
        let key_bytes = [42u8; 32];
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
        let (first_address, first_x, first_y) = private_key_to_address(&signing_key);

        let signing_key2 = SigningKey::from_slice(&key_bytes).unwrap();
        let (second_address, second_x, second_y) = private_key_to_address(&signing_key2);

        assert_eq!(first_address, second_address);
        assert_eq!(first_x, second_x);
        assert_eq!(first_y, second_y);
    }

    #[test]
    fn test_validate_private_key_range_valid() {
        let valid_key = [1u8; 32];
        assert!(validate_private_key_range(&valid_key).is_ok());
    }

    #[test]
    fn test_validate_private_key_range_zero() {
        let zero_key = [0u8; 32];
        assert!(validate_private_key_range(&zero_key).is_err());
    }

    #[test]
    fn test_validate_private_key_range_exceeds_order() {
        let mut exceeds_order = SECP256K1_ORDER;
        exceeds_order[31] = exceeds_order[31].wrapping_add(1);
        assert!(validate_private_key_range(&exceeds_order).is_err());
    }

    #[test]
    fn test_validate_private_key_range_equals_order() {
        let equals_order = SECP256K1_ORDER;
        assert!(validate_private_key_range(&equals_order).is_err());
    }

    #[test]
    fn test_validate_private_key_range_just_below_order() {
        let mut just_below = SECP256K1_ORDER;
        just_below[31] -= 1;
        assert!(validate_private_key_range(&just_below).is_ok());
    }

    #[test]
    fn test_validate_private_key_range_edge_case_near_order() {
        let mut edge_key = [0xFFu8; 32];
        edge_key[15] = 0xFD;
        assert!(validate_private_key_range(&edge_key).is_ok());
    }

    #[test]
    fn test_validate_private_key_range_edge_case_exceeds() {
        let mut edge_key = [0xFFu8; 32];
        edge_key[15] = 0xFF;
        assert!(validate_private_key_range(&edge_key).is_err());
    }

    #[test]
    fn test_load_index_map_invalid_format() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let index_path = temp_dir.path().join("invalid_index.txt");
        let mut file = std::fs::File::create(&index_path).unwrap();
        writeln!(file, "invalid_format_without_colon").unwrap();
        drop(file);

        let result = load_index_map(&index_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected 'address:index'"));
    }

    #[test]
    fn test_load_index_map_duplicate_address() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let index_path = temp_dir.path().join("dup_index.txt");
        let mut file = std::fs::File::create(&index_path).unwrap();
        writeln!(file, "0x1234567890123456789012345678901234567890:0").unwrap();
        writeln!(file, "0x1234567890123456789012345678901234567890:1").unwrap();
        drop(file);

        let result = load_index_map(&index_path);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_load_merkle_tree_invalid_level_format() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let tree_path = temp_dir.path().join("invalid_tree.txt");
        let mut file = std::fs::File::create(&tree_path).unwrap();
        writeln!(file, "invalid_line_without_colons").unwrap();
        drop(file);

        let result = load_merkle_tree(&tree_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_merkle_tree_duplicate_entry() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let tree_path = temp_dir.path().join("dup_tree.txt");
        let mut file = std::fs::File::create(&tree_path).unwrap();
        writeln!(
            file,
            "0:0:0x1234567890123456789012345678901234567890123456789012345678901234"
        )
        .unwrap();
        writeln!(
            file,
            "0:0:0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        .unwrap();
        drop(file);

        let result = load_merkle_tree(&tree_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate entry"));
    }

    #[test]
    fn test_load_merkle_tree_non_contiguous_indices() {
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let tree_path = temp_dir.path().join("noncontig_tree.txt");
        let mut file = std::fs::File::create(&tree_path).unwrap();
        writeln!(
            file,
            "0:0:0x1234567890123456789012345678901234567890123456789012345678901234"
        )
        .unwrap();
        writeln!(
            file,
            "0:2:0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        .unwrap();
        drop(file);

        let result = load_merkle_tree(&tree_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Non-contiguous indices"));
    }
}
