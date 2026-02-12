use anyhow::{Context, Result};
use clap::Parser;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

fn keccak256_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let hash = Keccak256::new()
        .chain_update(left)
        .chain_update(right)
        .finalize();
    hash.into()
}

fn address_to_leaf(address: &[u8; 20]) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[12..32].copy_from_slice(address);
    leaf
}

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

pub fn build_merkle_tree(leaves: Vec<[u8; 32]>) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
    let mut tree: Vec<Vec<[u8; 32]>> = vec![leaves];
    let mut level = tree[0].clone();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { left };
            next_level.push(keccak256_hash(left, right));
        }

        tree.push(next_level.clone());
        level = next_level;
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

        let addr_str = if trimmed.starts_with("0x") {
            &trimmed[2..]
        } else {
            trimmed
        };
        let mut address = [0u8; 20];
        hex::decode_to_slice(addr_str, &mut address).context("Invalid address format")?;
        let leaf = address_to_leaf(&address);
        index_map.insert(address, leaves.len());
        leaves.push(leaf);

        if (line_num + 1) % 1_000_000 == 0 {
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
