use dep::keccak256::keccak256;

global MERKLE_DEPTH: u32 = 26;
global DOMAIN_SEPARATOR_BYTE_0: u8 = 0xa1;
global DOMAIN_SEPARATOR_BYTE_1: u8 = 0xb2;
global DOMAIN_SEPARATOR_BYTE_2: u8 = 0xc3;
global DOMAIN_SEPARATOR_BYTE_3: u8 = 0xd4;

struct MerkleProof {
    path: [[u8; 32]; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
}

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

fn compute_nullifier(private_key_le_bytes: [u8; 32]) -> Field {
    let mut domain_padded: [u8; 32] = [0; 32];
    domain_padded[28] = DOMAIN_SEPARATOR_BYTE_0;
    domain_padded[29] = DOMAIN_SEPARATOR_BYTE_1;
    domain_padded[30] = DOMAIN_SEPARATOR_BYTE_2;
    domain_padded[31] = DOMAIN_SEPARATOR_BYTE_3;

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

fn address_to_leaf(address: [u8; 20]) -> [u8; 32] {
    let mut leaf: [u8; 32] = [0; 32];
    for i in 0..20 {
        leaf[i + 12] = address[i];
    }
    leaf
}

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

fn verify_private_key_ownership(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    claimed_address: Field,
) {
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

global SECP256K1_ORDER_BYTE_15: u8 = 0xFE;
global SECP256K1_ORDER_BYTE_16: u8 = 0xBA;
global SECP256K1_ORDER_BYTE_17: u8 = 0xAE;
global SECP256K1_ORDER_BYTE_18: u8 = 0xDC;
global SECP256K1_ORDER_BYTE_19: u8 = 0xE6;
global SECP256K1_ORDER_BYTE_20: u8 = 0xAF;
global SECP256K1_ORDER_BYTE_21: u8 = 0x48;
global SECP256K1_ORDER_BYTE_22: u8 = 0xA0;
global SECP256K1_ORDER_BYTE_23: u8 = 0x3B;
global SECP256K1_ORDER_BYTE_24: u8 = 0xBF;
global SECP256K1_ORDER_BYTE_25: u8 = 0xD2;
global SECP256K1_ORDER_BYTE_26: u8 = 0x5E;
global SECP256K1_ORDER_BYTE_27: u8 = 0x8C;
global SECP256K1_ORDER_BYTE_28: u8 = 0xD0;
global SECP256K1_ORDER_BYTE_29: u8 = 0x36;
global SECP256K1_ORDER_BYTE_30: u8 = 0x41;
global SECP256K1_ORDER_BYTE_31: u8 = 0x41;

fn validate_private_key_range(private_key_le_bytes: [u8; 32]) {
    let secp_order_le: [u8; 32] = [
        SECP256K1_ORDER_BYTE_31, SECP256K1_ORDER_BYTE_30, SECP256K1_ORDER_BYTE_29,
        SECP256K1_ORDER_BYTE_28, SECP256K1_ORDER_BYTE_27, SECP256K1_ORDER_BYTE_26,
        SECP256K1_ORDER_BYTE_25, SECP256K1_ORDER_BYTE_24, SECP256K1_ORDER_BYTE_23,
        SECP256K1_ORDER_BYTE_22, SECP256K1_ORDER_BYTE_21, SECP256K1_ORDER_BYTE_20,
        SECP256K1_ORDER_BYTE_19, SECP256K1_ORDER_BYTE_18, SECP256K1_ORDER_BYTE_17,
        SECP256K1_ORDER_BYTE_16, SECP256K1_ORDER_BYTE_15, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    let mut key_exceeds: bool = false;
    let mut all_equal_so_far: bool = true;

    for i in 0..32 {
        let key_byte = private_key_le_bytes[i];
        let order_byte = secp_order_le[i];

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
