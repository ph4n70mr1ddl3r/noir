use anyhow::{Context, Result};
use clap::Parser;
use k256::ecdsa::SigningKey;
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use airdrop_cli::{get_merkle_proof, parse_address, write_file_atomic};

const NULLIFIER_DOMAIN_SEPARATOR: [u8; 4] = 0xa1b2c3d4u32.to_be_bytes();

/// Converts a byte array to a hex string field representation.
///
/// # Arguments
/// * `bytes` - The byte array to convert
///
/// # Returns
/// Hex string with "0x" prefix
pub fn bytes_to_field(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

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
/// Uses Keccak256 with a domain separator to ensure uniqueness.
///
/// # Arguments
/// * `private_key_bytes` - 32-byte private key
///
/// # Returns
/// 32-byte nullifier hash
pub fn compute_nullifier(private_key_bytes: &[u8]) -> [u8; 32] {
    let hash = Keccak256::new()
        .chain_update(private_key_bytes)
        .chain_update(NULLIFIER_DOMAIN_SEPARATOR)
        .finalize();
    hash.into()
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

    println!("Loading Merkle tree...");
    let tree = load_merkle_tree(&cli.tree).context("Failed to load Merkle tree")?;

    println!("Loading index map...");
    let index_map = load_index_map(&cli.index_map).context("Failed to load index map")?;

    println!("Parsing private key...");
    let mut private_key_bytes = [0u8; 32];
    let key_str = if cli.private_key == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_line(&mut buffer)
            .context("Failed to read private key from stdin")?;
        buffer.trim().to_string()
    } else {
        cli.private_key.clone()
    };
    let key_str = key_str.strip_prefix("0x").unwrap_or(&key_str);
    hex::decode_to_slice(key_str, &mut private_key_bytes).context("Invalid private key format")?;

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

    println!("Computing nullifier...");
    let nullifier = compute_nullifier(&private_key_bytes);

    println!("Parsing recipient address...");
    let recipient = parse_address(&cli.recipient).context("Invalid recipient address")?;
    if recipient == [0u8; 20] {
        anyhow::bail!("Zero recipient address not allowed");
    }

    let claim = ClaimOutput {
        merkle_root: cli.root,
        recipient: format!("0x{}", hex::encode(recipient)),
        nullifier: format!("0x{}", hex::encode(nullifier)),
        merkle_proof: merkle_proof
            .iter()
            .map(|h| format!("0x{}", hex::encode(h)))
            .collect(),
        leaf_index,
        claimer_address: format!("0x{}", hex::encode(claimer_address)),
    };

    println!("Writing claim JSON to {:?}...", cli.output);
    let json_output = serde_json::to_string_pretty(&claim).context("Failed to serialize JSON")?;
    write_file_atomic(&cli.output, &json_output).context("Failed to write claim file")?;

    println!("\nClaim generated successfully!");
    println!("Claimer address: 0x{}", hex::encode(claimer_address));
    println!("Recipient: 0x{}", hex::encode(recipient));
    println!("Nullifier: 0x{}", hex::encode(nullifier));
    println!("Proof length: {} nodes", merkle_proof.len());

    Ok(())
}
