use airdrop_cli::{address_to_leaf, hex_encode, keccak256_hash, write_file_atomic};
use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const MAX_ADDRESSES: usize = 10_000_000;
const ESTIMATED_MEMORY_PER_ADDRESS: usize = 164;

#[derive(Parser)]
#[command(name = "build-tree")]
#[command(about = "Build Merkle tree from qualified accounts", long_about = None)]
struct Cli {
    /// Input file containing Ethereum addresses (one per line)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for Merkle root
    #[arg(short, long)]
    root_output: PathBuf,

    /// Output file for index map (address -> leaf index)
    #[arg(short, long)]
    index_output: PathBuf,

    /// Output file for Merkle tree (for proof generation)
    #[arg(short, long)]
    tree_output: Option<PathBuf>,
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
pub fn build_merkle_tree(leaves: Vec<[u8; 32]>) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
    assert!(
        !leaves.is_empty(),
        "Cannot build Merkle tree from empty leaves"
    );

    let mut tree: Vec<Vec<[u8; 32]>> = vec![leaves];
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

    (tree, root)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("Reading addresses from {:?}...", cli.input);
    let file = File::open(&cli.input).context("Failed to open input file")?;
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
        let leaf = address_to_leaf(&address);
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
                "Number of addresses exceeds maximum allowed ({})",
                MAX_ADDRESSES
            );
        }

        if leaves.len() == 1 {
            let estimated_mem = ESTIMATED_MEMORY_PER_ADDRESS * MAX_ADDRESSES;
            println!(
                "Warning: Building tree for up to {} addresses may use ~{}MB of memory",
                MAX_ADDRESSES,
                estimated_mem / 1_000_000
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

    println!("Building Merkle tree...");

    let (tree, root) = build_merkle_tree(leaves);

    println!("Merkle root: {}", hex_encode(root));

    let root_content = hex_encode(root);
    write_file_atomic(&cli.root_output, &root_content).context("Failed to write root file")?;

    let mut index_lines: Vec<String> = Vec::new();
    for (address, index) in &index_map {
        index_lines.push(format!("{}:{}", hex_encode(address), index));
    }
    let index_content = index_lines.join("\n");
    write_file_atomic(&cli.index_output, &index_content).context("Failed to write index file")?;

    if let Some(tree_path) = cli.tree_output {
        println!("Writing Merkle tree to {:?}...", tree_path);
        let mut tree_lines: Vec<String> = Vec::new();
        for (level_num, level) in tree.iter().enumerate() {
            for (i, hash) in level.iter().enumerate() {
                tree_lines.push(format!("{}:{}:{}", level_num, i, hex_encode(hash)));
            }
        }
        let tree_content = tree_lines.join("\n");
        write_file_atomic(&tree_path, &tree_content).context("Failed to write tree file")?;
    }

    println!("Done!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Cannot build Merkle tree from empty leaves")]
    fn test_build_merkle_tree_empty() {
        let leaves: Vec<[u8; 32]> = vec![];
        let _ = build_merkle_tree(leaves);
    }

    #[test]
    fn test_build_merkle_tree_single_leaf() {
        let leaves = vec![[1u8; 32]];
        let (tree, root) = build_merkle_tree(leaves);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].len(), 1);
        assert_eq!(root, tree[0][0]);
    }

    #[test]
    fn test_build_merkle_tree_two_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32]];
        let (tree, root) = build_merkle_tree(leaves);
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].len(), 2);
        assert_eq!(tree[1].len(), 1);
        let expected = keccak256_hash([1u8; 32], [2u8; 32]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_build_merkle_tree_odd_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let (tree, root) = build_merkle_tree(leaves);
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
        let (tree, _root) = build_merkle_tree(leaves);
        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].len(), 4);
        assert_eq!(tree[1].len(), 2);
        assert_eq!(tree[2].len(), 1);
    }
}
