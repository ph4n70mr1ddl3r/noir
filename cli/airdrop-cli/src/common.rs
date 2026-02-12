use sha3::{Digest, Keccak256};

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
/// Vector of sibling hashes forming the Merkle proof
pub fn get_merkle_proof(
    tree: &[Vec<[u8; 32]>],
    leaf_index: usize,
) -> anyhow::Result<Vec<[u8; 32]>> {
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
    let mut current_index = leaf_index;

    for level in tree.iter().skip(1) {
        if level.is_empty() {
            break;
        }

        let sibling_index = if current_index.is_multiple_of(2) {
            current_index + 1
        } else {
            current_index - 1
        };

        if sibling_index > 0 && sibling_index < level.len() {
            proof.push(level[sibling_index]);
        }

        current_index /= 2;
    }

    Ok(proof)
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
        let level2 = vec![[7u8; 32]];
        let tree = vec![level0, level1, level2];

        let proof = get_merkle_proof(&tree, 0).unwrap();
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0], [6u8; 32]);
    }

    #[test]
    fn test_get_merkle_proof_empty_tree() {
        let tree: Vec<Vec<[u8; 32]>> = vec![];
        let proof = get_merkle_proof(&tree, 0);
        assert!(proof.is_err());
    }

    #[test]
    fn test_get_merkle_proof_out_of_bounds() {
        let level0 = vec![[1u8; 32], [2u8; 32]];
        let tree = vec![level0];
        let proof = get_merkle_proof(&tree, 5);
        assert!(proof.is_err());
    }
}
