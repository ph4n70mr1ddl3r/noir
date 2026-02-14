//! Common utilities for the airdrop CLI tools.
//!
//! This module provides shared functionality for:
//! - Ethereum address parsing and validation
//! - Keccak256 hashing operations
//! - Merkle tree operations
//! - Atomic file operations

use sha3::{Digest, Keccak256};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during common operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CommonError {
    #[error("Invalid address length: expected 40 hex chars, got {0}")]
    InvalidAddressLength(usize),

    #[error("Invalid hex encoding: {0}")]
    InvalidHex(#[source] hex::FromHexError),

    #[error("Zero address not allowed")]
    ZeroAddress,

    #[error("Invalid merkle root length: expected 64 hex chars, got {0}")]
    InvalidRootLength(usize),

    #[error("Invalid merkle root: must not be zero")]
    ZeroRoot,

    #[error("Merkle tree is empty")]
    EmptyTree,

    #[error("Leaf index {index} is out of bounds for tree with {leaf_count} leaves (valid range: 0..{max_index})")]
    LeafIndexOutOfBounds {
        index: usize,
        leaf_count: usize,
        max_index: usize,
    },

    #[error("Encountered empty level {0} in Merkle tree")]
    EmptyLevel(usize),

    #[error("IO error: {0}")]
    Io(#[source] std::io::Error),

    #[error("Private key cannot be zero")]
    ZeroPrivateKey,

    #[error("Private key must be less than secp256k1 curve order")]
    PrivateKeyExceedsOrder,
}

/// Parses an Ethereum address from a hex string.
///
/// # Arguments
/// * `addr_str` - The address string, with or without "0x" prefix
///
/// # Returns
/// A 20-byte array representing the address
///
/// # Errors
/// Returns an error if the address is not 40 hex characters, contains invalid hex, or is zero
pub fn parse_address(addr_str: &str) -> Result<[u8; 20], CommonError> {
    let cleaned = addr_str
        .trim()
        .strip_prefix("0x")
        .unwrap_or(addr_str.trim());
    if cleaned.len() != 40 {
        return Err(CommonError::InvalidAddressLength(cleaned.len()));
    }
    let mut address = [0u8; 20];
    hex::decode_to_slice(cleaned, &mut address).map_err(CommonError::InvalidHex)?;
    if address == [0u8; 20] {
        return Err(CommonError::ZeroAddress);
    }
    Ok(address)
}

/// Computes a Keccak256 hash of two 32-byte values concatenated.
///
/// # Arguments
/// * `left` - First 32-byte value
/// * `right` - Second 32-byte value
///
/// # Returns
/// 32-byte hash result
#[must_use]
#[inline]
pub fn keccak256_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let hash = Keccak256::new()
        .chain_update(left)
        .chain_update(right)
        .finalize();
    hash.into()
}

/// Converts byte data to hex string with 0x prefix.
///
/// # Arguments
/// * `data` - Byte data to encode
///
/// # Returns
/// Hex string with "0x" prefix
#[must_use]
#[inline]
pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode(data.as_ref()))
}

/// Validates a Merkle root hex string.
///
/// # Arguments
/// * `root` - Merkle root string, with or without "0x" prefix
///
/// # Returns
/// 32-byte array representing the Merkle root
///
/// # Errors
/// Returns an error if the root is not 64 hex characters, contains invalid hex, or is zero
pub fn validate_merkle_root(root: &str) -> Result<[u8; 32], CommonError> {
    let cleaned = root.trim().strip_prefix("0x").unwrap_or(root.trim());
    if cleaned.len() != 64 {
        return Err(CommonError::InvalidRootLength(cleaned.len()));
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(cleaned, &mut bytes).map_err(CommonError::InvalidHex)?;
    if bytes == [0u8; 32] {
        return Err(CommonError::ZeroRoot);
    }
    Ok(bytes)
}

/// Converts a 20-byte Ethereum address to a 32-byte Merkle leaf.
///
/// Pads the address with zeros on the left (12 bytes of zeros + 20-byte address).
///
/// # Arguments
/// * `address` - 20-byte Ethereum address
///
/// # Returns
/// 32-byte Merkle leaf
#[must_use]
#[inline]
pub fn address_to_leaf(address: [u8; 20]) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[12..32].copy_from_slice(&address);
    leaf
}

pub const MERKLE_DEPTH: usize = 26;

pub const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Domain separator bytes for nullifier computation to prevent cross-context replay.
/// Must match the value in Noir circuit: [0xa1, 0xb2, 0xc3, 0xd4] placed at bytes 28-31.
pub const DOMAIN_SEPARATOR_BYTES: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

/// Validates that a private key is within the valid range for secp256k1.
///
/// The key must be non-zero and less than the curve order n.
///
/// # Arguments
/// * `key_bytes` - 32-byte private key (big-endian)
///
/// # Errors
/// Returns an error if the key is zero or >= curve order
#[inline]
pub fn validate_private_key_range(key_bytes: &[u8; 32]) -> Result<(), CommonError> {
    if key_bytes == &[0u8; 32] {
        return Err(CommonError::ZeroPrivateKey);
    }

    for i in 0..32 {
        match key_bytes[i].cmp(&SECP256K1_ORDER[i]) {
            std::cmp::Ordering::Less => return Ok(()),
            std::cmp::Ordering::Greater => {
                return Err(CommonError::PrivateKeyExceedsOrder);
            }
            std::cmp::Ordering::Equal => continue,
        }
    }

    Err(CommonError::PrivateKeyExceedsOrder)
}

/// Generates a Merkle proof for a leaf at the given index.
///
/// The proof is always padded to MERKLE_DEPTH (26) elements by hashing the current
/// root with itself for any remaining levels. This ensures compatibility with the
/// Noir circuit which expects exactly 26 proof elements.
///
/// # Padding Behavior
///
/// When the tree has fewer than 26 levels (i.e., fewer than 2^26 leaves), the proof
/// is padded by:
/// 1. Adding the current computed hash as the sibling
/// 2. Setting the index to `true` (left child)
/// 3. Hashing the current hash with itself to get the next level
///
/// This matches the behavior in `build_merkle_tree` where odd nodes are hashed with
/// themselves to maintain the binary tree structure.
///
/// # Arguments
/// * `tree` - The Merkle tree as a vector of levels
/// * `leaf_index` - Index of the leaf in the tree
///
/// # Returns
/// A tuple containing:
/// - Vector of exactly MERKLE_DEPTH sibling hashes forming the Merkle proof
/// - Vector of exactly MERKLE_DEPTH booleans indicating direction (true = leaf is left child)
///
/// # Errors
/// Returns an error if the tree is empty, the index is out of bounds, or the tree structure is invalid
pub fn get_merkle_proof(
    tree: &[Vec<[u8; 32]>],
    leaf_index: usize,
) -> Result<(Vec<[u8; 32]>, Vec<bool>), CommonError> {
    if tree.is_empty() {
        return Err(CommonError::EmptyTree);
    }
    if leaf_index >= tree[0].len() {
        return Err(CommonError::LeafIndexOutOfBounds {
            index: leaf_index,
            leaf_count: tree[0].len(),
            max_index: tree[0].len().saturating_sub(1),
        });
    }

    let mut proof = Vec::with_capacity(MERKLE_DEPTH);
    let mut indices = Vec::with_capacity(MERKLE_DEPTH);
    let mut current_index = leaf_index;
    let mut current_hash = tree[0][leaf_index];

    for (depth, level) in tree.iter().enumerate().take(tree.len() - 1) {
        if level.is_empty() {
            return Err(CommonError::EmptyLevel(depth));
        }

        let is_left = current_index % 2 == 0;
        let sibling_index = if is_left {
            current_index + 1
        } else {
            current_index - 1
        };

        let sibling = if sibling_index >= level.len() {
            level[current_index]
        } else {
            level[sibling_index]
        };

        proof.push(sibling);
        indices.push(is_left);

        current_hash = if is_left {
            keccak256_hash(current_hash, sibling)
        } else {
            keccak256_hash(sibling, current_hash)
        };
        current_index /= 2;
    }

    while proof.len() < MERKLE_DEPTH {
        proof.push(current_hash);
        indices.push(true);
        current_hash = keccak256_hash(current_hash, current_hash);
    }

    Ok((proof, indices))
}

/// Atomically writes content to a file using a temp file and rename.
///
/// # Arguments
/// * `path` - Target file path
/// * `content` - Content to write
///
/// # Errors
/// Returns an error if file operations fail
///
/// # Security
/// On Unix systems, the temp file is created with mode 0o600 (owner read/write only)
/// to prevent unauthorized access before the atomic rename.
pub fn write_file_atomic<P: AsRef<Path>>(path: P, content: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let path = path.as_ref();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_path = path.with_extension(format!("{}.{}.tmp", std::process::id(), timestamp));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
    }

    let cleanup = scopeguard::guard((), |()| {
        let _ = std::fs::remove_file(&temp_path);
    });

    std::fs::rename(&temp_path, path)?;
    scopeguard::ScopeGuard::into_inner(cleanup);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_with_prefix() {
        let addr = "0x1234567890abcdef1234567890abcdef12345678";
        let result = parse_address(addr).unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_parse_address_without_prefix() {
        let addr = "1234567890abcdef1234567890abcdef12345678";
        let result = parse_address(addr).unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_parse_address_invalid_length() {
        let addr = "0x1234";
        let result = parse_address(addr);
        assert!(matches!(result, Err(CommonError::InvalidAddressLength(4))));
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        let addr = "0xghijklmnopqrstuvwxyz1234567890abcdef";
        let result = parse_address(addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_address_zero() {
        let addr = "0x0000000000000000000000000000000000000000";
        let result = parse_address(addr);
        assert!(matches!(result, Err(CommonError::ZeroAddress)));
    }

    #[test]
    fn test_address_to_leaf() {
        let address: [u8; 20] = [1u8; 20];
        let leaf = address_to_leaf(address);
        assert_eq!(leaf[0..12], [0u8; 12]);
        assert_eq!(leaf[12..32], address);
    }

    #[test]
    fn test_keccak256_hash() {
        let left: [u8; 32] = [1u8; 32];
        let right: [u8; 32] = [2u8; 32];
        let hash = keccak256_hash(left, right);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_get_merkle_proof() {
        let level0 = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let level1 = vec![[5u8; 32], [6u8; 32]];
        let tree = vec![level0, level1];

        let (proof, indices) = get_merkle_proof(&tree, 0).unwrap();
        assert_eq!(proof.len(), MERKLE_DEPTH);
        assert_eq!(proof[0], [2u8; 32]);
        assert_eq!(indices.len(), MERKLE_DEPTH);
        assert!(indices[0]);
    }

    #[test]
    fn test_get_merkle_proof_empty_tree() {
        let tree: Vec<Vec<[u8; 32]>> = vec![];
        let result = get_merkle_proof(&tree, 0);
        assert!(matches!(result, Err(CommonError::EmptyTree)));
    }

    #[test]
    fn test_get_merkle_proof_out_of_bounds() {
        let level0 = vec![[1u8; 32], [2u8; 32]];
        let tree = vec![level0];
        let result = get_merkle_proof(&tree, 5);
        assert!(matches!(
            result,
            Err(CommonError::LeafIndexOutOfBounds {
                index: 5,
                leaf_count: 2,
                ..
            })
        ));
        if let Err(CommonError::LeafIndexOutOfBounds {
            index: idx,
            leaf_count: len,
            ..
        }) = result
        {
            assert_eq!(idx, 5);
            assert_eq!(len, 2);
            let msg = format!(
                "{}",
                CommonError::LeafIndexOutOfBounds {
                    index: 5,
                    leaf_count: 2,
                    max_index: 1
                }
            );
            assert!(msg.contains('5'));
            assert!(msg.contains('2'));
        }
    }

    #[test]
    fn test_get_merkle_proof_odd_tree_last_leaf() {
        let level0 = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let hash1 = keccak256_hash([1u8; 32], [2u8; 32]);
        let hash2 = keccak256_hash([3u8; 32], [3u8; 32]);
        let root = keccak256_hash(hash1, hash2);
        let level1 = vec![hash1, hash2];
        let level2 = vec![root];
        let tree = vec![level0, level1, level2];

        let (proof, indices) = get_merkle_proof(&tree, 2).unwrap();
        assert_eq!(proof.len(), MERKLE_DEPTH);
        assert_eq!(proof[0], [3u8; 32]);
        assert!(indices[0]);
    }

    #[test]
    fn test_hex_encode() {
        let data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = hex_encode(data);
        assert_eq!(result, "0xdeadbeef");
    }

    #[test]
    fn test_validate_merkle_root_valid() {
        let root = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = validate_merkle_root(root).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_validate_merkle_root_invalid_length() {
        let root = "0x1234";
        let result = validate_merkle_root(root);
        assert!(matches!(result, Err(CommonError::InvalidRootLength(4))));
    }

    #[test]
    fn test_validate_merkle_root_invalid_hex() {
        let root = "0xghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890";
        let result = validate_merkle_root(root);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_merkle_root_zero() {
        let root = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let result = validate_merkle_root(root);
        assert!(matches!(result, Err(CommonError::ZeroRoot)));
    }

    #[test]
    fn test_write_file_atomic() {
        use std::io::Read;

        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join("test_write_file_atomic.txt");

        let content = "test content\nline 2";
        let result = write_file_atomic(&test_path, content);
        assert!(result.is_ok());

        let mut file = std::fs::File::open(&test_path).unwrap();
        let mut read_content = String::new();
        file.read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content, content);

        let _ = std::fs::remove_file(&test_path);
    }

    #[test]
    fn test_write_file_atomic_overwrite() {
        use std::io::Read;

        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join("test_write_file_atomic_overwrite.txt");

        write_file_atomic(&test_path, "original content").unwrap();
        write_file_atomic(&test_path, "new content").unwrap();

        let mut file = std::fs::File::open(&test_path).unwrap();
        let mut read_content = String::new();
        file.read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content, "new content");

        let _ = std::fs::remove_file(&test_path);
    }

    #[test]
    fn test_get_merkle_proof_single_leaf() {
        let single_leaf = vec![[42u8; 32]];
        let root = single_leaf[0];
        let tree = vec![single_leaf, vec![root]];

        let (proof, indices) = get_merkle_proof(&tree, 0).unwrap();
        assert_eq!(proof.len(), MERKLE_DEPTH);
        assert_eq!(indices.len(), MERKLE_DEPTH);
        assert!(indices.iter().all(|&x| x));
    }

    #[test]
    fn test_get_merkle_proof_two_leaves() {
        let level0 = vec![[1u8; 32], [2u8; 32]];
        let root = keccak256_hash([1u8; 32], [2u8; 32]);
        let tree = vec![level0, vec![root]];

        let (proof_left, indices_left) = get_merkle_proof(&tree, 0).unwrap();
        assert_eq!(proof_left[0], [2u8; 32]);
        assert!(indices_left[0]);

        let (proof_right, indices_right) = get_merkle_proof(&tree, 1).unwrap();
        assert_eq!(proof_right[0], [1u8; 32]);
        assert!(!indices_right[0]);
    }

    #[test]
    fn test_address_to_leaf_consistency() {
        let address: [u8; 20] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let leaf1 = address_to_leaf(address);
        let leaf2 = address_to_leaf(address);
        assert_eq!(leaf1, leaf2);
    }

    #[test]
    fn test_keccak256_hash_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash1 = keccak256_hash(left, right);
        let hash2 = keccak256_hash(left, right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak256_hash_different_inputs() {
        let left1 = [1u8; 32];
        let right1 = [2u8; 32];
        let hash1 = keccak256_hash(left1, right1);

        let left2 = [2u8; 32];
        let right2 = [1u8; 32];
        let hash2 = keccak256_hash(left2, right2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_parse_address_case_insensitive() {
        let lower = "0xabcdef0123456789abcdef0123456789abcdef01";
        let upper = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01";

        let result_lower = parse_address(lower).unwrap();
        let result_upper = parse_address(upper).unwrap();

        assert_eq!(result_lower, result_upper);
    }
}
