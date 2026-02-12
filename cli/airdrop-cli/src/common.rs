use sha3::{Digest, Keccak256};

pub fn keccak256_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let hash = Keccak256::new()
        .chain_update(left)
        .chain_update(right)
        .finalize();
    hash.into()
}

pub fn address_to_leaf(address: &[u8; 20]) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[12..32].copy_from_slice(address);
    leaf
}

pub fn get_merkle_proof(tree: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut current_index = leaf_index;

    for level in tree.iter().skip(1) {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        if sibling_index < level.len() {
            proof.push(level[sibling_index]);
        }

        current_index /= 2;
    }

    proof
}
