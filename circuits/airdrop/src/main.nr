use std::hash::keccak256;
use std::ec::sec_p256k1;
use std::hash::poseidon2;

// Maximum depth for Merkle tree (2^26 = ~67M accounts)
global MERKLE_DEPTH = 26;
// Domain separator for nullifier computation to prevent cross-context replay
global NULLIFIER_DOMAIN_SEPARATOR = 0xa1b2c3d4;
// secp256k1 curve order for private key validation
global SECP256K1_ORDER: Field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

struct MerkleProof {
    path: [Field; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
}

fn compute_merkle_root(leaf: Field, proof: MerkleProof) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_DEPTH {
        if proof.indices[i] {
            current = poseidon2([current, proof.path[i]]);
        } else {
            current = poseidon2([proof.path[i], current]);
        }
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
    let hash = keccak256([private_key, Field::from(NULLIFIER_DOMAIN_SEPARATOR)]);
    hash
}

fn address_to_leaf(address: Field) -> Field {
    // Pad address to 32 bytes (multiply by 2^96 to left-pad with 12 zeros)
    address * Field::from(79228162514264337593543950336)
}

fn main(
    merkle_root: Field,
    recipient: Field,
    public_nullifier: Field,
    private_key: Field,
    proof: MerkleProof,
) {
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