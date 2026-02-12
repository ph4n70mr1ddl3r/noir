use std::hash::poseidon2;

global MERKLE_DEPTH = 26;
global NULLIFIER_DOMAIN_SEPARATOR = 0xa1b2c3d4;

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

fn derive_address(private_key: Field) -> Field {
    poseidon2([private_key])
}

fn validate_private_key(private_key: Field) {
    assert(private_key != Field::from(0));
}

fn compute_nullifier(private_key: Field) -> Field {
    poseidon2([private_key, Field::from(NULLIFIER_DOMAIN_SEPARATOR)])
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
    let computed_root = compute_merkle_root(address, proof);
    assert(computed_root == merkle_root);

    let computed_nullifier = compute_nullifier(private_key);
    assert(computed_nullifier == public_nullifier);
}