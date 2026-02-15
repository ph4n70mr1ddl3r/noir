#![forbid(unsafe_code)]

use airdrop_cli::{address_to_leaf, hex_encode, keccak256_hash, write_file_atomic, MERKLE_DEPTH};
use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const MAX_ADDRESSES: usize = 1 << MERKLE_DEPTH;
const MAX_INPUT_FILE_SIZE: u64 = 500 * 1024 * 1024;
/// Estimated memory usage per address in bytes.
/// Breakdown: 32 bytes (leaf hash) + 32 bytes (HashMap entry overhead) +
/// ~100 bytes (HashMap bucket + allocation overhead) = ~164 bytes
const ESTIMATED_MEMORY_PER_ADDRESS: usize = 164;

type MerkleTreeLevel = Vec<[u8; 32]>;
type MerkleTree = Vec<MerkleTreeLevel>;

#[derive(Parser, Debug)]
#[command(name = "build-tree")]
#[command(about = "Build Merkle tree from qualified accounts", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Input file containing Ethereum addresses (one per line)
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output file for Merkle root
    #[arg(short, long)]
    pub root_output: PathBuf,

    /// Output file for index map (address -> leaf index)
    #[arg(short, long)]
    pub index_output: PathBuf,

    /// Output file for Merkle tree (for proof generation)
    #[arg(short, long)]
    pub tree_output: Option<PathBuf>,
}

/// Builds a Merkle tree from a list of leaf hashes.
///
/// # Arguments
/// * `leaves` - Vector of 32-byte leaf hashes (must not be empty)
///
/// # Returns
/// A tuple containing the tree (vector of levels) and the root hash
///
/// # Note
/// For odd number of nodes at any level, the last node is duplicated
/// (hashed with itself) to maintain the binary tree structure.
pub fn build_merkle_tree(leaves: MerkleTreeLevel) -> Result<(MerkleTree, [u8; 32])> {
    if leaves.is_empty() {
        anyhow::bail!("Cannot build Merkle tree from empty leaves");
    }

    let mut tree: MerkleTree = vec![leaves];
    let mut current_level = tree.last().unwrap();

    while current_level.len() > 1 {
        let next_level_capacity = current_level.len().div_ceil(2);
        let mut next_level = Vec::with_capacity(next_level_capacity);

        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };
            next_level.push(keccak256_hash(left, right));
        }

        tree.push(next_level);
        current_level = tree.last().unwrap();
    }

    let root = tree.last().map(|level| level[0]).unwrap_or([0u8; 32]);

    Ok((tree, root))
}

pub fn run(cli: Cli) -> Result<()> {
    println!("Reading addresses from {:?}...", cli.input);
    let file = File::open(&cli.input).context("Failed to open input file")?;
    let metadata = file.metadata().context("Failed to get file metadata")?;
    let file_size = metadata.len();
    if file_size > MAX_INPUT_FILE_SIZE {
        anyhow::bail!(
            "Input file too large: {} bytes (max {} bytes)",
            file_size,
            MAX_INPUT_FILE_SIZE
        );
    }
    let reader = BufReader::new(file);

    let mut leaves = Vec::new();
    let mut index_map = HashMap::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read line")?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        let address = airdrop_cli::parse_address(trimmed)
            .with_context(|| format!("Invalid address format at line {}", line_num + 1))?;
        let leaf = address_to_leaf(address);
        if index_map.contains_key(&address) {
            anyhow::bail!(
                "Duplicate address found at line {}: 0x{}",
                line_num + 1,
                hex::encode(address)
            );
        }
        index_map.insert(address, leaves.len());
        leaves.push(leaf);

        if leaves.len() > MAX_ADDRESSES {
            anyhow::bail!(
                "Number of addresses ({}) exceeds maximum allowed ({}). Consider splitting your input file into multiple batches.",
                leaves.len(),
                MAX_ADDRESSES
            );
        }

        if (line_num + 1) % 100_000 == 0 {
            println!("Processed {} addresses...", line_num + 1);
        }
    }

    println!("Total addresses: {}", leaves.len());
    if leaves.is_empty() {
        anyhow::bail!("No valid addresses found in input file");
    }

    let estimated_mem = ESTIMATED_MEMORY_PER_ADDRESS.saturating_mul(leaves.len());
    println!(
        "Building Merkle tree for {} addresses (~{}MB estimated memory)...",
        leaves.len(),
        estimated_mem / 1_000_000
    );

    let (tree, root) = build_merkle_tree(leaves).context("Failed to build Merkle tree")?;

    println!("Merkle root: {}", hex_encode(root));

    let root_content = format!("{}\n", hex_encode(root));
    write_file_atomic(&cli.root_output, &root_content).context("Failed to write root file")?;

    let mut index_entries: Vec<(&[u8; 20], &usize)> = index_map.iter().collect();
    index_entries.sort_by_key(|(_, &idx)| idx);
    let mut index_lines: Vec<String> = Vec::new();
    for (address, index) in index_entries {
        index_lines.push(format!("{}:{}", hex_encode(address), index));
    }
    let index_content = format!("{}\n", index_lines.join("\n"));
    write_file_atomic(&cli.index_output, &index_content).context("Failed to write index file")?;

    if let Some(tree_path) = cli.tree_output {
        println!("Writing Merkle tree to {:?}...", tree_path);
        let mut tree_lines: Vec<String> = Vec::new();
        for (level_num, level) in tree.iter().enumerate() {
            for (i, hash) in level.iter().enumerate() {
                tree_lines.push(format!("{}:{}:{}", level_num, i, hex_encode(hash)));
            }
        }
        let tree_content = format!("{}\n", tree_lines.join("\n"));
        write_file_atomic(&tree_path, &tree_content).context("Failed to write tree file")?;
    }

    println!("Done!");
    Ok(())
}

#[allow(dead_code)]
fn main() -> Result<()> {
    run(Cli::parse())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_merkle_tree_empty() {
        let leaves: Vec<[u8; 32]> = vec![];
        let result = build_merkle_tree(leaves);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_merkle_tree_single_leaf() {
        let leaves = vec![[1u8; 32]];
        let (tree, root) = build_merkle_tree(leaves).unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].len(), 1);
        assert_eq!(root, tree[0][0]);
    }

    #[test]
    fn test_build_merkle_tree_two_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32]];
        let (tree, root) = build_merkle_tree(leaves).unwrap();
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].len(), 2);
        assert_eq!(tree[1].len(), 1);
        let expected = keccak256_hash([1u8; 32], [2u8; 32]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_build_merkle_tree_odd_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let (tree, root) = build_merkle_tree(leaves).unwrap();
        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].len(), 3);
        assert_eq!(tree[1].len(), 2);
        assert_eq!(tree[2].len(), 1);
        let hash1 = keccak256_hash([1u8; 32], [2u8; 32]);
        let hash2 = keccak256_hash([3u8; 32], [3u8; 32]);
        let expected = keccak256_hash(hash1, hash2);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_build_merkle_tree_power_of_two() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
        let (tree, _root) = build_merkle_tree(leaves).unwrap();
        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].len(), 4);
        assert_eq!(tree[1].len(), 2);
        assert_eq!(tree[2].len(), 1);
    }

    #[test]
    fn test_build_merkle_tree_consistency() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let (tree1, root1) = build_merkle_tree(leaves.clone()).unwrap();
        let (tree2, root2) = build_merkle_tree(leaves).unwrap();

        assert_eq!(root1, root2);
        assert_eq!(tree1.len(), tree2.len());
    }

    #[test]
    fn test_build_merkle_tree_order_matters() {
        let leaves1 = vec![[1u8; 32], [2u8; 32]];
        let leaves2 = vec![[2u8; 32], [1u8; 32]];

        let (_, root1) = build_merkle_tree(leaves1).unwrap();
        let (_, root2) = build_merkle_tree(leaves2).unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_build_merkle_tree_large() {
        let leaves: Vec<[u8; 32]> = (0..100)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr
            })
            .collect();

        let (tree, root) = build_merkle_tree(leaves).unwrap();

        assert!(!root.iter().all(|&b| b == 0));
        assert!(tree.len() > 1);
    }
}
