use std::hash::keccak256;
use std::ec::sec_p256k1;

// Maximum depth for Merkle tree (2^26 = ~67M accounts)
// This supports all Ethereum accounts with room for growth
global MERKLE_DEPTH = 26;

// Domain separator bytes for nullifier computation to prevent cross-context replay
// Must match CLI: [0xa1, 0xb2, 0xc3, 0xd4] placed at bytes 28-31 of 32-byte array
// This ensures nullifiers are unique to this airdrop system and cannot be replayed
// on other contracts or systems
global DOMAIN_SEPARATOR_BYTES: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

// secp256k1 curve order for private key validation
// Private keys must be in range [1, n-1] where n is the curve order
global SECP256K1_ORDER: Field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

// Left shift amount to pad 20-byte address to 32 bytes (2^96 = 0x1000000000000000000000000)
// Ethereum addresses are 20 bytes, but Merkle tree leaves are 32 bytes
// This shift places the address in the rightmost 20 bytes (same as Solidity uint256(address))
global ADDRESS_LEFT_SHIFT: Field = 0x1000000000000000000000000;

// Merkle proof structure containing sibling hashes and position indicators
// path: array of sibling hashes at each level of the tree
// indices: boolean array indicating if the current node is the left child (true) or right child (false)
struct MerkleProof {
    path: [Field; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
}

// Computes the Merkle root from a leaf and proof
// Iteratively hashes the current node with its sibling, following the path up the tree
// Uses Keccak256 for compatibility with Ethereum's hashing
fn compute_merkle_root(leaf: Field, proof: MerkleProof) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_DEPTH {
        // Determine which value is left and which is right based on position
        let left: [u8; 32] = if proof.indices[i] {
            current.to_le_bytes()
        } else {
            proof.path[i].to_le_bytes()
        };
        let right: [u8; 32] = if proof.indices[i] {
            proof.path[i].to_le_bytes()
        } else {
            current.to_le_bytes()
        };
        // Hash left || right to get parent node
        let hash = keccak256([left, right]);
        current = hash;
    }

    current
}

// Derives Ethereum address from secp256k1 private key using ECDSA
// Matches standard Ethereum address derivation: last 20 bytes of Keccak256(uncompressed public key)
// The public key is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
// We strip the 0x04 prefix and hash the remaining 64 bytes
fn derive_address(private_key: Field) -> Field {
    let secret_key = sec_p256k1::SecretKey::from_field(private_key);
    let public_key = secret_key.public_key();
    let public_key_bytes = public_key.to_bytes();
    // Remove the 0x04 prefix byte to get raw x,y coordinates
    let mut pub_key_trimmed: [u8; 64] = [0; 64];
    for i in 0..64 {
        pub_key_trimmed[i] = public_key_bytes[i + 1];
    }
    // Hash the uncompressed public key (without prefix)
    let hash = keccak256([pub_key_trimmed]);
    // Take last 20 bytes as the address
    let mut address = Field::from(0);
    for i in 0..20 {
        let byte = (hash >> ((31 - i) * 8)) & 0xFF;
        address = address * 256 + byte;
    }
    address
}

// Validates that the private key is in valid range for secp256k1
// Must be non-zero and less than the curve order n
fn validate_private_key(private_key: Field) {
    assert(private_key != Field::from(0));
    assert(private_key < SECP256K1_ORDER);
}

// Computes nullifier using Keccak256 to prevent double-claiming
// The nullifier is H(private_key_le || domain_separator)
// Using little-endian for the private key to match Noir's to_le_bytes() behavior
// The domain separator ensures nullifiers are unique to this airdrop system
fn compute_nullifier(private_key: Field) -> Field {
    let mut domain_padded: [u8; 32] = [0; 32];
    domain_padded[28] = DOMAIN_SEPARATOR_BYTES[0];
    domain_padded[29] = DOMAIN_SEPARATOR_BYTES[1];
    domain_padded[30] = DOMAIN_SEPARATOR_BYTES[2];
    domain_padded[31] = DOMAIN_SEPARATOR_BYTES[3];
    let hash = keccak256([private_key.to_le_bytes(), domain_padded]);
    hash
}

// Converts a 20-byte Ethereum address to a 32-byte Merkle tree leaf
// Left-pads with zeros: leaf = address << 96
// This matches Solidity's uint256(address) conversion
fn address_to_leaf(address: Field) -> Field {
    address * ADDRESS_LEFT_SHIFT
}

// Main ZK circuit for private airdrop claims
//
// This circuit proves:
// 1. The prover knows a private key that corresponds to an address in the Merkle tree
// 2. The nullifier is correctly derived from the private key
// 3. The recipient address is valid (non-zero)
//
// Public inputs (revealed to verifier):
// - merkle_root: The root of the qualified addresses Merkle tree
// - recipient: The address to receive the tokens (can differ from claimer)
// - public_nullifier: Unique identifier to prevent double claims
//
// Private inputs (kept secret):
// - private_key: The claimer's private key (never revealed on-chain)
// - proof: Merkle proof showing the derived address is in the tree
fn main(
    merkle_root: Field,
    recipient: Field,
    public_nullifier: Field,
    private_key: Field,
    proof: MerkleProof,
) {
    // Validate inputs are non-zero
    assert(merkle_root != Field::from(0));
    validate_private_key(private_key);
    assert(recipient != Field::from(0));
    assert(public_nullifier != Field::from(0));

    // Derive address from private key and verify Merkle membership
    let address = derive_address(private_key);
    let leaf = address_to_leaf(address);
    let computed_root = compute_merkle_root(leaf, proof);
    assert(computed_root == merkle_root);

    // Verify nullifier is correctly derived from private key
    let computed_nullifier = compute_nullifier(private_key);
    assert(computed_nullifier == public_nullifier);
}