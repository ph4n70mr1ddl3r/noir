# Noir ZK Airdrop System

A privacy-preserving airdrop system built with Noir, allowing 65M+ Ethereum accounts to claim ERC20 tokens with zero-knowledge proofs.

## Architecture

```
[65M Qualified Accounts] -> [Merkle Tree] -> [Merkle Root]
                                                      |
                                                      v
                                              [Smart Contract]
                                                      ^
                                                      |
[User] -> [CLI Tool] -> [Noir Proof] -> [Proof + Nullifier] -> [Claim]
```

## Project Structure

```
noir/
├── circuits/
│   └── airdrop/           # Noir ZK circuit
│       ├── Nargo.toml
│       └── src/main.nr
├── contracts/
│   └── Airdrop.sol        # Solidity airdrop contract
├── cli/
│   └── airdrop-cli/       # Rust CLI tools
│       ├── Cargo.toml
│       ├── src/
│       │   ├── build_tree.rs
│       │   ├── claim.rs
│       │   └── lib.rs
├── scripts/               # Helper scripts
└── README.md
```

## Prerequisites

- Rust (1.70+)
- Node.js (for Noir toolchain)
- Foundry/Hardhat (for contract deployment)
- Noir compiler (`nargo`)

## Setup

### 1. Install Noir

```bash
# Install nargo
curl -L https://raw.githubusercontent.com/noir-lang/noir/main/install_nargo.sh | bash

# Verify installation
nargo --version
```

### 2. Build Noir Circuit

```bash
cd circuits/airdrop
nargo compile
nargo prove
```

### 3. Generate Verifier Contract

```bash
# Generate Solidity verifier from Noir circuit
bb write_vk -b target/airdrop.json -o target/vk
bb contract -b target/airdrop.json -o ../contracts/verifier.sol
```

### 4. Build Rust CLI

```bash
cd cli/airdrop-cli
cargo build --release
```

## Usage

### Phase 1: Build Merkle Tree

Create a file with qualified accounts (one address per line):

```bash
# Example: accounts.txt
0x1234567890123456789012345678901234567890
0xabcdefabcdefabcdefabcdefabcdefabcdefabcd
...
```

Build the Merkle tree:

```bash
./target/release/build-tree \
  --input accounts.txt \
  --root-output merkle_root.txt \
  --index-output index_map.txt \
  --tree-output merkle_tree.txt
```

This outputs:
- `merkle_root.txt`: Merkle root for the smart contract
- `index_map.txt`: Maps addresses to their leaf indices
- `merkle_tree.txt`: Full Merkle tree for proof generation

### Phase 2: Deploy Smart Contract

Deploy the verifier and airdrop contracts:

```bash
# Deploy verifier first (generated from Noir)
forge create verifier.sol:UltraVerifier --private-key $PK

# Deploy airdrop contract
forge create contracts/Airdrop.sol:Airdrop \
  --constructor-args \
  $TOKEN_ADDRESS \
  $VERIFIER_ADDRESS \
  $(cat merkle_root.txt) \
  --private-key $PK
```

### Phase 3: User Claims

Users generate their claim proof locally:

```bash
# Download the publicly available Merkle tree files
wget https://your-domain.com/merkle_tree.txt
wget https://your-domain.com/index_map.txt

# Generate claim
./target/release/claim \
  --tree merkle_tree.txt \
  --index-map index_map.txt \
  --private-key YOUR_PRIVATE_KEY \
  --recipient YOUR_WALLET_ADDRESS \
  --root $(cat merkle_root.txt) \
  --output claim.json
```

The generated `claim.json` contains:
```json
{
  "merkle_root": "0x...",
  "recipient": "0x...",
  "nullifier": "0x...",
  "merkle_proof": ["0x...", "0x...", ...],
  "merkle_indices": [true, false, ...],
  "leaf_index": 12345,
  "claimer_address": "0x..."
}
```

### Phase 3.5: Generate Noir Proof

Generate the actual zero-knowledge proof from the claim JSON:

```bash
./target/release/prove \
  --input claim.json \
  --circuit ../../circuits/airdrop \
  --output proof.json
```

The generated `proof.json` contains:
```json
{
  "proof": ["0x...", "0x...", ...],
  "public_inputs": ["0x...", "0x...", "0x..."]
}
```

### Phase 4: Submit Proof to Contract

Users submit their claim to the smart contract:

```bash
cast send $AIRDROP_ADDRESS \
  "claim(uint256[],bytes32,address)" \
  "[proof1,proof2,...]" \
  "0xnullifier..." \
  "0xrecipient..." \
  --private-key $PK
```

## Security Features

1. **Nullifiers**: Prevents double-spending from the same account
2. **Privacy**: Private key never exposed on-chain
3. **Merkle Proof**: Verifies membership in qualified list
4. **Deterministic Nullifier**: Same address always generates same nullifier

## Performance

- **Merkle Tree**: 65M addresses → 26 levels
- **Proof Size**: ~26 Merkle nodes + Noir proof
- **Gas Cost**: ~200k-300k gas per claim (varies by network)

## Customization

### Change Claim Amount

Edit `contracts/Airdrop.sol`:

```solidity
uint256 public constant CLAIM_AMOUNT = 100 * 10**18; // Change this
```

### Adjust Merkle Depth

Edit `circuits/airdrop/src/main.nr`:

```rust
global MERKLE_DEPTH = 26; // Adjust for your tree size
```

## Notes

- The Merkle tree file can be large (several GB for 65M accounts)
- Consider hosting the tree files on IPFS or a CDN for public access
- The nullifier is deterministic per private key, preventing multiple claims
- Private key is only used locally to generate the proof, never sent to the contract

## Troubleshooting

### Address not found in qualified list
Ensure the private key corresponds to an address in your original accounts.txt

### Invalid proof
Check that:
- Merkle root matches contract root
- Noir circuit version matches verifier
- All proof fields are correctly formatted

### Out of memory when building tree
Increase Rust stack size or process in smaller batches

## License

MIT