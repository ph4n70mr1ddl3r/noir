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
    get_merkle_proof, hex_encode, parse_address, validate_merkle_root, write_file_atomic,
};

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
    leaf_index: usize,
    claimer_address: String,
}

/// Computes a nullifier from a private key to prevent double-claiming.
///
/// Uses Keccak256 with a domain separator for cryptographic strength.
/// Consistent with Noir circuit implementation.
///
/// # Arguments
/// * `private_key_bytes` - 32-byte private key
///
/// # Returns
/// 32-byte nullifier hash
pub fn compute_nullifier(private_key_bytes: &[u8]) -> Result<[u8; 32]> {
    // Domain separator from circuit: 0xa1b2c3d4
    let domain_separator: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
    let mut hasher = Keccak256::new();
    hasher.update(private_key_bytes);
    hasher.update(domain_separator);
    let result = hasher.finalize();
    Ok(result.into())
}

fn load_index_map(path: &PathBuf) -> Result<HashMap<[u8; 20], usize>> {
    let file = File::open(path).context("Failed to open index map file")?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

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

fn load_merkle_tree(path: &PathBuf) -> Result<Vec<Vec<[u8; 32]>>> {
    let file = File::open(path).context("Failed to open Merkle tree file")?;
    let reader = BufReader::new(file);

    let mut max_level = 0usize;
    let mut level_entries: Vec<HashMap<usize, [u8; 32]>> = Vec::new();

    for line in reader.lines() {
        let line = line.context("Failed to read line")?;
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let level: usize = parts[0].parse().context("Invalid level format")?;
            let index: usize = parts[1].parse().context("Invalid index format")?;
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
            max_level = max_level.max(level);
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("Validating Merkle root...");
    let _ = validate_merkle_root(&cli.root).context("Invalid Merkle root")?;

    println!("Loading Merkle tree...");
    let tree = load_merkle_tree(&cli.tree).context("Failed to load Merkle tree")?;

    println!("Loading index map...");
    let index_map = load_index_map(&cli.index_map).context("Failed to load index map")?;

    println!("Parsing private key...");
    let key_str = if cli.private_key == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_line(&mut buffer)
            .context("Failed to read private key from stdin")?;
        let trimmed = buffer.trim().to_string();
        buffer.zeroize();
        trimmed
    } else {
        cli.private_key.clone()
    };
    let key_str = key_str.strip_prefix("0x").unwrap_or(&key_str);
    if key_str.is_empty() {
        anyhow::bail!("Private key is empty");
    }
    let mut key_bytes = hex::decode(key_str).context("Invalid private key format")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid private key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(&key_bytes);
    key_bytes.zeroize();

    let signing_key = SigningKey::from_slice(&private_key_bytes).context("Invalid private key")?;

    println!("Deriving address from private key...");
    let claimer_address = private_key_to_address(&signing_key)?;

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
    let merkle_proof =
        get_merkle_proof(&tree, leaf_index).context("Failed to generate Merkle proof")?;

    if merkle_proof.is_empty() && !tree.is_empty() && tree[0].len() > 1 {
        anyhow::bail!("Invalid Merkle proof: proof is empty but tree has multiple leaves");
    }

    println!("Computing nullifier...");
    let nullifier = compute_nullifier(&private_key_bytes)?;

    private_key_bytes.zeroize();

    println!("Parsing recipient address...");
    let recipient = parse_address(&cli.recipient).context("Invalid recipient address")?;
    if recipient == [0u8; 20] {
        anyhow::bail!("Zero recipient address not allowed");
    }

    let claim = ClaimOutput {
        merkle_root: cli.root,
        recipient: hex_encode(recipient),
        nullifier: hex_encode(nullifier),
        merkle_proof: merkle_proof.iter().copied().map(hex_encode).collect(),
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
    fn test_compute_nullifier() {
        let key = [1u8; 32];
        let nullifier1 = compute_nullifier(&key).unwrap();
        let nullifier2 = compute_nullifier(&key).unwrap();
        assert_eq!(nullifier1, nullifier2);

        let key2 = [2u8; 32];
        let nullifier3 = compute_nullifier(&key2).unwrap();
        assert_ne!(nullifier1, nullifier3);
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
}
