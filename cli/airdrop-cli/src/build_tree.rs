use airdrop_cli::{address_to_leaf, keccak256_hash};
use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

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
/// * `leaves` - Vector of 32-byte leaf hashes
///
/// # Returns
/// A tuple containing the tree (vector of levels) and the root hash
pub fn build_merkle_tree(leaves: Vec<[u8; 32]>) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
    if leaves.is_empty() {
        return (vec![], [0u8; 32]);
    }

    let mut tree: Vec<Vec<[u8; 32]>> = vec![leaves];
    let mut level = &tree[0];

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { left };
            next_level.push(keccak256_hash(left, right));
        }

        tree.push(next_level);
        level = tree.last().unwrap();
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

        if (line_num + 1) % 100_000 == 0 {
            println!("Processed {} addresses...", line_num + 1);
        }
    }

    println!("Total addresses: {}", leaves.len());
    println!("Building Merkle tree...");

    let (tree, root) = build_merkle_tree(leaves);

    println!("Merkle root: 0x{}", hex::encode(root));

    let mut root_file = File::create(&cli.root_output).context("Failed to create root file")?;
    writeln!(root_file, "0x{}", hex::encode(root)).context("Failed to write root")?;

    let mut index_file = File::create(&cli.index_output).context("Failed to create index file")?;
    for (address, index) in &index_map {
        writeln!(index_file, "0x{}:{}", hex::encode(address), index)
            .context("Failed to write index")?;
    }

    if let Some(tree_path) = cli.tree_output {
        println!("Writing Merkle tree to {:?}...", tree_path);
        let mut tree_file = File::create(&tree_path).context("Failed to create tree file")?;

        for (level_num, level) in tree.iter().enumerate() {
            for (i, hash) in level.iter().enumerate() {
                writeln!(tree_file, "{}:{}:0x{}", level_num, i, hex::encode(hash))
                    .context("Failed to write tree")?;
            }
        }
    }

    println!("Done!");
    Ok(())
}
