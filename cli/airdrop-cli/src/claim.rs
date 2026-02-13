use anyhow::{Context, Result};
use clap::Parser;
use k256::ecdsa::SigningKey;
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use zeroize::Zeroize;

use airdrop_cli::{
    get_merkle_proof, hex_encode, keccak256_hash, parse_address, validate_merkle_root,
    write_file_atomic,
};

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

const MERKLE_DEPTH: usize = 26;

#[derive(Parser)]
#[command(name = "claim")]
#[command(about = "Generate airdrop claim proof", long_about = None)]
struct Cli {
    /// Path to Merkle tree file
    #[arg(short = 't', long)]
    tree: PathBuf,

    /// Path to index map file
    #[arg(short = 'i', long)]
    index_map: PathBuf,

    /// Private key (hex format, with or without 0x prefix)
    /// Alternatively, use "-" to read from stdin (more secure)
    #[arg(short = 'k', long)]
    private_key: String,

    /// Recipient address (where to receive tokens)
    #[arg(short = 'r', long)]
    recipient: String,

    /// Output JSON file
    #[arg(short, long)]
    output: PathBuf,

    /// Merkle root (hex format)
    #[arg(short, long)]
    root: String,
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
}

const DOMAIN_SEPARATOR_BYTES: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

/// Computes a nullifier from a private key to prevent double-claiming.
///
/// Uses Keccak256 with a domain separator for cryptographic strength.
/// Consistent with Noir circuit implementation which uses to_le_bytes().
///
/// # Arguments
/// * `private_key_bytes` - 32-byte private key (big-endian hex format)
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

fn load_index_map(path: &PathBuf) -> Result<HashMap<[u8; 20], usize>> {
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

fn load_merkle_tree(path: &PathBuf) -> Result<Vec<Vec<[u8; 32]>>> {
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

fn private_key_to_address(signing_key: &SigningKey) -> Result<[u8; 20]> {
    let public_key = signing_key.verifying_key();
    let encoded = public_key.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();
    let hash = Keccak256::digest(&pub_bytes[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    Ok(address)
}

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

fn main() -> Result<()> {
    let mut cli = Cli::parse();

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
    let claimer_address = private_key_to_address(&signing_key)?;
    drop(signing_key);

    println!("Computing nullifier...");
    let nullifier = compute_nullifier(&private_key_bytes)?;
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

    let actual_depth = merkle_proof.len();
    if actual_depth != MERKLE_DEPTH {
        anyhow::bail!(
            "Tree depth ({}) does not match expected MERKLE_DEPTH ({}). The Noir circuit expects exactly {} levels. Either rebuild the tree with at least 2^{} leaves, or adjust MERKLE_DEPTH in both the CLI and circuit.",
            actual_depth,
            MERKLE_DEPTH,
            MERKLE_DEPTH,
            MERKLE_DEPTH
        );
    }

    println!("Parsing recipient address...");
    let recipient = parse_address(&cli.recipient).context("Invalid recipient address")?;

    let claim = ClaimOutput {
        merkle_root: hex_encode(merkle_root),
        recipient: hex_encode(recipient),
        nullifier: hex_encode(nullifier),
        merkle_proof: merkle_proof.iter().copied().map(hex_encode).collect(),
        merkle_indices,
        leaf_index,
        claimer_address: hex_encode(claimer_address),
    };

    println!("Writing claim JSON to {:?}...", cli.output);
    let json_output = serde_json::to_string_pretty(&claim).context("Failed to serialize JSON")?;
    write_file_atomic(&cli.output, &json_output).context("Failed to write claim file")?;

    println!("\nClaim generated successfully!");
    println!("Claimer address: {}", hex_encode(claimer_address));
    println!("Recipient: {}", hex_encode(recipient));
    println!("Nullifier: {}", hex_encode(nullifier));
    println!("Proof length: {} nodes", merkle_proof.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_private_key_to_address() {
        let key_bytes = [1u8; 32];
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
        let address = private_key_to_address(&signing_key).unwrap();
        assert_eq!(address.len(), 20);
        assert_ne!(address, [0u8; 20]);
    }

    #[test]
    fn test_private_key_to_address_deterministic() {
        let key_bytes = [42u8; 32];
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
        let address1 = private_key_to_address(&signing_key).unwrap();

        let signing_key2 = SigningKey::from_slice(&key_bytes).unwrap();
        let address2 = private_key_to_address(&signing_key2).unwrap();

        assert_eq!(address1, address2);
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
}
