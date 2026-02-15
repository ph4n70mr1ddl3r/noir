# Noir ZK Airdrop - Project Summary

## Overview

A complete zero-knowledge proof airdrop system built with Noir, supporting 65M+ Ethereum accounts with privacy-preserving claims.

## Project Structure

```
noir/
├── circuits/airdrop/          # Noir ZK Circuit
│   ├── Nargo.toml            # Noir package config
│   └── src/main.nr           # Main circuit (Merkle proof + nullifier)
│
├── contracts/
│   └── Airdrop.sol           # Solidity airdrop contract
│
├── cli/airdrop-cli/          # Rust CLI Tools
│   ├── Cargo.toml            # Rust dependencies
│   └── src/
│       ├── build_tree.rs     # Merkle tree builder (65M+ accounts)
│       ├── claim.rs          # Generate claim + Merkle proof
│       ├── prove.rs          # Generate Noir ZK proof
│       └── lib.rs            # Library exports
│
├── scripts/
│   └── DeployAirdrop.s.sol   # Foundry deployment script
│
├── sample_accounts.txt       # Example qualified accounts
├── quickstart.sh             # Automated setup script
├── foundry.toml              # Foundry config
├── .gitignore               # Git ignore rules
├── README.md                # Main documentation
└── EXAMPLE_WORKFLOW.md      # Step-by-step guide
```

## Components

### 1. Noir Circuit (`circuits/airdrop/src/main.nr`)

**Inputs:**
- Public: `merkle_root`, `recipient`, `public_nullifier`
- Private: `private_key`, `merkle_proof`

**Logic:**
1. Derive address from private key
2. Verify Merkle proof (address ∈ qualified list)
3. Compute deterministic nullifier (prevents double claims)

**Depth:** 26 levels (supports up to 67M accounts)

### 2. Rust CLI Tools

#### `build-tree` - Merkle Tree Builder
- Reads 65M+ addresses from file
- Builds Merkle tree efficiently
- Outputs: root, index map, full tree

#### `claim` - Claim Generator
- Takes private key + recipient address
- Generates Merkle proof
- Computes nullifier
- Outputs JSON with all claim data

#### `prove` - Noir Proof Generator
- Reads claim JSON
- Generates ZK proof using Noir circuit
- Outputs proof + public inputs

### 3. Smart Contract (`contracts/Airdrop.sol`)

**Features:**
- Store Merkle root
- Track used nullifiers (prevent double claims)
- Verify Noir proofs
- Distribute ERC20 tokens

**Functions:**
- `claim()`: Submit proof + claim tokens
- `updateRoot()`: Update Merkle root (owner only)
- `withdrawTokens()`: Withdraw unclaimed tokens

## Security Features

1. **Nullifiers**: Prevents double-spending (deterministic per private key)
2. **Privacy**: Private key never exposed on-chain
3. **Merkle Proof**: Verifies membership in qualified list
4. **ZK Proof**: Guarantees proof validity without revealing private key

## Performance

- **Merkle Tree**: 65M addresses → 26 levels
- **Proof Size**: ~26 Merkle nodes + Noir proof (~1-2KB)
- **Gas Cost**: ~200k-300k gas per claim
- **Tree Build Time**: ~10-30 minutes for 65M addresses

## Dependencies

**Rust CLI:**
- `clap` - CLI argument parsing
- `serde/json` - JSON handling
- `k256` - Elliptic curve cryptography
- `sha3` - Keccak hashing
- `hex` - Hex encoding/decoding

**Noir:**
- `keccak256` crate for hashing
- Standard library (ecdsa_secp256k1 for signature verification)

**Solidity:**
- Foundry framework
- Custom Noir verifier

## Workflow

```
1. Setup: Compile circuit, build CLI tools
2. Deployer: Build Merkle tree → Deploy contracts
3. User: Download tree → Generate claim → Generate proof → Submit
```

## Files Summary

| File | Purpose |
|------|---------|
| `circuits/airdrop/src/main.nr` | Noir ZK circuit logic |
| `contracts/Airdrop.sol` | Smart contract for proof verification |
| `cli/airdrop-cli/src/build_tree.rs` | Build Merkle from account list |
| `cli/airdrop-cli/src/claim.rs` | Generate claim JSON |
| `cli/airdrop-cli/src/prove.rs` | Generate Noir proof |
| `scripts/DeployAirdrop.s.sol` | Foundry deployment script |
| `quickstart.sh` | One-command setup |
| `README.md` | Main documentation |
| `EXAMPLE_WORKFLOW.md` | Step-by-step examples |

## Next Steps

1. **Install Noir**: Run `./quickstart.sh`
2. **Build Tree**: Process your 65M accounts
3. **Deploy**: Deploy verifier + airdrop contracts
4. **Distribute**: Share tree files publicly for users
5. **Claim**: Users generate proofs and claim tokens

## Customization

- **Claim Amount**: Edit `contracts/Airdrop.sol` `CLAIM_AMOUNT` constant
- **Tree Depth**: Edit `circuits/airdrop/src/main.nr` line 3
- **Hash Function**: Replace Keccak with Poseidon2 in CLI tools

## Notes

- Merkle tree files can be several GB (host on IPFS/CDN)
- Each address can claim only once
- Private keys used only locally, never transmitted
- Verifier contract must be generated from same Noir circuit version