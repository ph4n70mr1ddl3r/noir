//! Airdrop CLI library for Noir ZK airdrop system.
//!
//! This crate provides common utilities for building Merkle trees,
//! generating claims, and creating ZK proofs for the airdrop system.

pub mod common;

pub use common::{
    address_to_leaf, get_merkle_proof, hex_encode, keccak256_hash, parse_address,
    validate_merkle_root, write_file_atomic, CommonError, MERKLE_DEPTH,
};
