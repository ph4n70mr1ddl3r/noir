//! Airdrop CLI library for Noir ZK airdrop system.
//!
//! This crate provides common utilities for building Merkle trees,
//! generating claims, and creating ZK proofs for the airdrop system.

#![forbid(unsafe_code)]

pub mod common;

pub use common::{
    address_to_leaf, get_merkle_proof, hex_encode, keccak256_hash, parse_address,
    validate_merkle_root, validate_private_key_range, write_file_atomic, CommonError,
    DOMAIN_SEPARATOR_BYTES, MERKLE_DEPTH, SECP256K1_HALF_ORDER, SECP256K1_ORDER,
};
