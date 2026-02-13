use std::hash::keccak256;
use std::ec::sec_p256k1;

// Maximum depth for Merkle tree (2^26 = ~67M accounts)
global MERKLE_DEPTH = 26;
// Domain separator bytes for nullifier computation to prevent cross-context replay
// Must match CLI: [0xa1, 0xb2, 0xc3, 0xd4] placed at bytes 28-31 of 32-byte array
global DOMAIN_SEPARATOR_BYTES: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
// secp256k1 curve order for private key validation
global SECP256K1_ORDER: Field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
// Left shift amount to pad 20-byte address to 32 bytes (2^96 = 0x1000000000000000000000000)
global ADDRESS_LEFT_SHIFT: Field = 0x1000000000000000000000000;

struct MerkleProof {
    path: [Field; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
}

fn compute_merkle_root(leaf: Field, proof: MerkleProof) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_DEPTH {
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
        let hash = keccak256([left, right]);
        current = hash;
    }

    current
}

// Derives Ethereum address from secp256k1 private key using ECDSA
// Matches standard Ethereum address derivation: last 20 bytes of Keccak256(public key)
fn derive_address(private_key: Field) -> Field {
    let secret_key = sec_p256k1::SecretKey::from_field(private_key);
    let public_key = secret_key.public_key();
    let public_key_bytes = public_key.to_bytes();
    let mut pub_key_trimmed: [u8; 64] = [0; 64];
    for i in 0..64 {
        pub_key_trimmed[i] = public_key_bytes[i + 1];
    }
    let hash = keccak256([pub_key_trimmed]);
    let mut address = Field::from(0);
    for i in 0..20 {
        let byte = (hash >> ((31 - i) * 8)) & 0xFF;
        address = address * 256 + byte;
    }
    address
}

fn validate_private_key(private_key: Field) {
    assert(private_key != Field::from(0));
    assert(private_key < SECP256K1_ORDER);
}

// Computes nullifier using Keccak256 to prevent double-claiming
// Consistent with CLI nullifier computation (HMAC-Keccak256 in CLI, Keccak256 here)
fn compute_nullifier(private_key: Field) -> Field {
    let mut domain_padded: [u8; 32] = [0; 32];
    domain_padded[28] = DOMAIN_SEPARATOR_BYTES[0];
    domain_padded[29] = DOMAIN_SEPARATOR_BYTES[1];
    domain_padded[30] = DOMAIN_SEPARATOR_BYTES[2];
    domain_padded[31] = DOMAIN_SEPARATOR_BYTES[3];
    let hash = keccak256([private_key.to_le_bytes(), domain_padded]);
    hash
}

fn address_to_leaf(address: Field) -> Field {
    address * ADDRESS_LEFT_SHIFT
}

fn main(
    merkle_root: Field,
    recipient: Field,
    public_nullifier: Field,
    private_key: Field,
    proof: MerkleProof,
) {
    assert(merkle_root != Field::from(0));
    validate_private_key(private_key);

    let address = derive_address(private_key);
    let leaf = address_to_leaf(address);
    let computed_root = compute_merkle_root(leaf, proof);
    assert(computed_root == merkle_root);

    let computed_nullifier = compute_nullifier(private_key);
    assert(computed_nullifier == public_nullifier);

    assert(recipient != Field::from(0));
    assert(public_nullifier != Field::from(0));
}