use sha3::{Digest, Keccak256};
use std::path::Path;

/// Parses an Ethereum address from a hex string.
///
/// # Arguments
/// * `addr_str` - The address string, with or without "0x" prefix
///
/// # Returns
/// A 20-byte array representing the address
///
/// # Errors
/// Returns an error if the address is not 40 hex characters or contains invalid hex
pub fn parse_address(addr_str: &str) -> anyhow::Result<[u8; 20]> {
    let cleaned = addr_str
        .trim()
        .strip_prefix("0x")
        .unwrap_or(addr_str.trim());
    if cleaned.len() != 40 {
        anyhow::bail!(
            "Invalid address length: expected 40 hex chars, got {}",
            cleaned.len()
        );
    }
    let mut address = [0u8; 20];
    hex::decode_to_slice(cleaned, &mut address)
        .map_err(|e| anyhow::anyhow!("Invalid hex encoding: {}", e))?;
    if address == [0u8; 20] {
        anyhow::bail!("Zero address not allowed");
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
/// Returns an error if the root is not 64 hex characters or contains invalid hex
pub fn validate_merkle_root(root: &str) -> anyhow::Result<[u8; 32]> {
    let cleaned = root.trim().strip_prefix("0x").unwrap_or(root.trim());
    if cleaned.len() != 64 {
        anyhow::bail!(
            "Invalid merkle root length: expected 64 hex chars, got {}",
            cleaned.len()
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(cleaned, &mut bytes)
        .map_err(|e| anyhow::anyhow!("Invalid merkle root hex encoding: {}", e))?;
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
pub fn address_to_leaf(address: &[u8; 20]) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[12..32].copy_from_slice(address);
    leaf
}

/// Generates a Merkle proof for a leaf at the given index.
///
/// # Arguments
/// * `tree` - The Merkle tree as a vector of levels
/// * `leaf_index` - Index of the leaf in the tree
///
/// # Returns
/// A tuple containing:
/// - Vector of sibling hashes forming the Merkle proof
/// - Vector of booleans indicating direction (true = leaf is left child)
pub fn get_merkle_proof(
    tree: &[Vec<[u8; 32]>],
    leaf_index: usize,
) -> anyhow::Result<(Vec<[u8; 32]>, Vec<bool>)> {
    if tree.is_empty() {
        anyhow::bail!("Merkle tree is empty");
    }
    if leaf_index >= tree[0].len() {
        anyhow::bail!(
            "Leaf index {} is out of bounds for tree with {} leaves",
            leaf_index,
            tree[0].len()
        );
    }

    let mut proof = Vec::new();
    let mut indices = Vec::new();
    let mut current_index = leaf_index;

    if tree.len() < 2 {
        return Ok((proof, indices));
    }

    for (depth, level) in tree.iter().enumerate().take(tree.len() - 1) {
        if level.is_empty() {
            anyhow::bail!("Encountered empty level {} in Merkle tree", depth);
        }

        let is_left = current_index % 2 == 0;
        let sibling_index = if is_left {
            current_index + 1
        } else {
            current_index - 1
        };

        if sibling_index >= level.len() {
            anyhow::bail!(
                "Sibling index {} is out of bounds for level {} with {} nodes",
                sibling_index,
                depth,
                level.len()
            );
        }

        proof.push(level[sibling_index]);
        indices.push(is_left);
        current_index /= 2;
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
pub fn write_file_atomic<P: AsRef<Path>>(path: P, content: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let path = path.as_ref();
    let temp_path = path.with_extension("tmp");

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
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
    }

    let cleanup = scopeguard::guard((), |_| {
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
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        let addr = "0xghijklmnopqrstuvwxyz1234567890abcdef";
        let result = parse_address(addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_to_leaf() {
        let address: [u8; 20] = [1u8; 20];
        let leaf = address_to_leaf(&address);
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
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0], [2u8; 32]);
        assert_eq!(indices.len(), 1);
        assert!(indices[0]);
    }

    #[test]
    fn test_get_merkle_proof_empty_tree() {
        let tree: Vec<Vec<[u8; 32]>> = vec![];
        let result = get_merkle_proof(&tree, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_merkle_proof_out_of_bounds() {
        let level0 = vec![[1u8; 32], [2u8; 32]];
        let tree = vec![level0];
        let result = get_merkle_proof(&tree, 5);
        assert!(result.is_err());
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
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_merkle_root_invalid_hex() {
        let root = "0xghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890";
        let result = validate_merkle_root(root);
        assert!(result.is_err());
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
}
