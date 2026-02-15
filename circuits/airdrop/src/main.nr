use dep::keccak256::keccak256;

// MERKLE_DEPTH of 26 supports up to 67,108,864 (2^26) leaves in the Merkle tree.
// This is chosen to balance between supporting large airdrops and keeping
// proof generation/verification efficient. Each additional level adds one
// hash operation to proof generation.
global MERKLE_DEPTH: u32 = 26;

// Domain separator for nullifier computation to prevent cross-context replay attacks.
// Must match the value in Solidity contract (Airdrop.sol) and CLI (common.rs).
global DOMAIN_SEPARATOR: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

// Merkle proof structure containing the sibling hashes and direction indicators.
struct MerkleProof {
    path: [[u8; 32]; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
}

// Computes the Merkle root from a leaf and a proof.
// Follows standard Merkle tree construction: H(left || right) where left/right
// are determined by the indices array.
fn compute_merkle_root(leaf: [u8; 32], proof: MerkleProof) -> [u8; 32] {
    let mut current = leaf;

    for i in 0..MERKLE_DEPTH {
        let left: [u8; 32] = if proof.indices[i] {
            current
        } else {
            proof.path[i]
        };
        let right: [u8; 32] = if proof.indices[i] {
            proof.path[i]
        } else {
            current
        };

        let mut input: [u8; 64] = [0; 64];
        for j in 0..32 {
            input[j] = left[j];
            input[j + 32] = right[j];
        }
        current = keccak256(input, 64);
    }

    current
}

// Derives an Ethereum address from an uncompressed secp256k1 public key.
// Uses standard Ethereum derivation: last 20 bytes of Keccak256(pubkey).
fn derive_address_from_pubkey(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> Field {
    let mut pub_key_uncompressed: [u8; 65] = [0; 65];
    pub_key_uncompressed[0] = 0x04;
    for i in 0..32 {
        pub_key_uncompressed[i + 1] = pub_key_x[i];
        pub_key_uncompressed[i + 33] = pub_key_y[i];
    }

    let hash = keccak256(pub_key_uncompressed, 65);

    let mut address: Field = 0;
    for i in 12..32 {
        let byte = hash[i];
        address = address * 256 + byte as Field;
    }
    address
}

// Computes a nullifier from a private key for double-claim prevention.
// Uses Keccak256(private_key_le || domain_separator) where private_key is
// converted to little-endian bytes for consistent encoding.
fn compute_nullifier(private_key_le_bytes: [u8; 32]) -> Field {
    let mut domain_padded: [u8; 32] = [0; 32];
    domain_padded[28] = DOMAIN_SEPARATOR[0];
    domain_padded[29] = DOMAIN_SEPARATOR[1];
    domain_padded[30] = DOMAIN_SEPARATOR[2];
    domain_padded[31] = DOMAIN_SEPARATOR[3];

    let mut input: [u8; 64] = [0; 64];
    for i in 0..32 {
        input[i] = private_key_le_bytes[i];
        input[i + 32] = domain_padded[i];
    }

    let hash = keccak256(input, 64);

    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + hash[i] as Field;
    }
    result
}

// Converts a 20-byte Ethereum address to a 32-byte Merkle leaf.
// Left-pads with zeros (12 bytes of zeros + 20-byte address).
fn address_to_leaf(address: [u8; 20]) -> [u8; 32] {
    let mut leaf: [u8; 32] = [0; 32];
    for i in 0..20 {
        leaf[i + 12] = address[i];
    }
    leaf
}

// Converts a Field value to a 20-byte address.
// Uses big-endian encoding consistent with Ethereum address representation.
fn field_to_address_bytes(address: Field) -> [u8; 20] {
    let mut bytes: [u8; 20] = [0; 20];
    let mut addr = address;
    for i in 0..20 {
        let quotient = addr / 256;
        let remainder = addr - quotient * 256;
        bytes[19 - i] = remainder as u8;
        addr = quotient;
    }
    bytes
}

// Verifies that the signer of the message owns the private key for the claimed address.
// This proves ownership without revealing the private key on-chain.
fn verify_private_key_ownership(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    claimed_address: Field,
) {
    // Validate that public key is not all zeros
    let mut pubkey_nonzero: bool = false;
    for i in 0..32 {
        if public_key_x[i] != 0 || public_key_y[i] != 0 {
            pubkey_nonzero = true;
        }
    }
    assert(pubkey_nonzero);

    let derived_address = derive_address_from_pubkey(public_key_x, public_key_y);
    assert(derived_address == claimed_address);

    let address_bytes = field_to_address_bytes(claimed_address);

    let mut message: [u8; 32] = [0; 32];
    for i in 0..20 {
        message[i + 12] = address_bytes[i];
    }
    let message_hash = keccak256(message, 32);

    let is_valid = std::ecdsa_secp256k1::verify_signature(
        public_key_x,
        public_key_y,
        signature,
        message_hash,
    );
    assert(is_valid);
}

// secp256k1 curve order in little-endian format.
// Used to validate that private keys are within valid range (1 <= key < n).
global SECP256K1_ORDER_LE: [u8; 32] = [
    0x41, 0x41, 0x36, 0xD0, 0x8C, 0x5E, 0xD2, 0xBF,
    0x3B, 0xA0, 0x48, 0xAF, 0xE6, 0xDC, 0xAE, 0xBA,
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

// Half of secp256k1 curve order in big-endian format (n/2).
// Used to prevent ECDSA signature malleability by enforcing low-s values.
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
// Note: This is big-endian because ECDSA signatures use big-endian encoding.
global SECP256K1_HALF_ORDER_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
    0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

// Validates that a private key is within the valid range for secp256k1.
// The key must be non-zero and less than the curve order n.
fn validate_private_key_range(private_key_le_bytes: [u8; 32]) {
    let mut key_exceeds: bool = false;
    let mut all_equal_so_far: bool = true;

    for i in 0..32 {
        let key_byte = private_key_le_bytes[i];
        let order_byte = SECP256K1_ORDER_LE[i];

        if all_equal_so_far {
            if key_byte > order_byte {
                key_exceeds = true;
            }
            if key_byte != order_byte {
                all_equal_so_far = false;
            }
        }
    }

    if all_equal_so_far {
        key_exceeds = true;
    }

    assert(!key_exceeds);
}

// Validates that the signature's s-value is in the lower half of the curve order.
// This prevents ECDSA signature malleability where (r, s) and (r, n-s) are both valid.
// By enforcing low-s, we ensure signature uniqueness.
// Also validates that the signature is not all zeros.
// Note: The signature is in big-endian format (standard ECDSA encoding).
fn validate_signature_low_s(signature: [u8; 64]) {
    // Check that signature is not all zeros
    let mut is_nonzero: bool = false;
    for i in 0..64 {
        if signature[i] != 0 {
            is_nonzero = true;
        }
    }
    assert(is_nonzero);

    // s is the second 32 bytes of the signature (big-endian)
    let mut s_exceeds: bool = false;
    let mut all_equal_so_far: bool = true;

    for i in 0..32 {
        let s_byte = signature[i + 32];
        let half_order_byte = SECP256K1_HALF_ORDER_BE[i];

        if all_equal_so_far {
            if s_byte > half_order_byte {
                s_exceeds = true;
            }
            if s_byte != half_order_byte {
                all_equal_so_far = false;
            }
        }
    }

    // If s equals exactly half_order, that's also not allowed (must be strictly less)
    if all_equal_so_far {
        s_exceeds = true;
    }

    assert(!s_exceeds);
}

// Main circuit entry point.
// Proves:
// 1. The claimer owns a private key for the claimed address
// 2. The claimed address is in the Merkle tree
// 3. The nullifier is correctly derived from the private key
// 4. The private key is within valid secp256k1 range
fn main(
    merkle_root: Field,
    recipient: Field,
    public_nullifier: Field,
    private_key_le_bytes: [u8; 32],
    claimed_address: Field,
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    proof: MerkleProof,
) {
    assert(merkle_root != 0);
    assert(recipient != 0);
    assert(public_nullifier != 0);
    assert(claimed_address != 0);

    let mut is_nonzero: bool = false;
    for i in 0..32 {
        if private_key_le_bytes[i] != 0 {
            is_nonzero = true;
        }
    }
    assert(is_nonzero);

    validate_private_key_range(private_key_le_bytes);

    validate_signature_low_s(signature);

    verify_private_key_ownership(
        public_key_x,
        public_key_y,
        signature,
        claimed_address,
    );

    let address_bytes = field_to_address_bytes(claimed_address);
    let leaf = address_to_leaf(address_bytes);
    let computed_root_bytes = compute_merkle_root(leaf, proof);

    let mut computed_root_field: Field = 0;
    for i in 0..32 {
        computed_root_field = computed_root_field * 256 + computed_root_bytes[i] as Field;
    }
    assert(computed_root_field == merkle_root);

    let computed_nullifier = compute_nullifier(private_key_le_bytes);
    assert(computed_nullifier == public_nullifier);
}
