# Example Workflow

This document walks through a complete example of setting up and using the Noir ZK Airdrop system.

## Step 1: Setup

```bash
# Clone and setup
cd noir
chmod +x quickstart.sh
./quickstart.sh
```

This will:
1. Install Noir toolchain
2. Compile the Noir circuit
3. Build the Rust CLI tools
4. Generate a sample Merkle tree

## Step 2: Build Your Merkle Tree

Create a file `accounts.txt` with your qualified addresses:

```bash
cat > accounts.txt << EOF
0x1234567890123456789012345678901234567890
0xabcdefabcdefabcdefabcdefabcdefabcdefabcd
0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359
EOF
```

Build the Merkle tree:

```bash
cd cli/airdrop-cli
cargo build --release
cd ../..

./cli/airdrop-cli/target/release/build-tree \
  --input accounts.txt \
  --root-output merkle_root.txt \
  --index-output index_map.txt \
  --tree-output merkle_tree.txt
```

You'll see output like:
```
Reading addresses from "accounts.txt"...
Processed 3 addresses...
Total addresses: 3
Building Merkle tree...
Merkle root: 0xabc123...
Writing Merkle tree to "merkle_tree.txt"...
Done!
```

## Step 3: Deploy Contracts

```bash
# Generate verifier from Noir circuit
cd circuits/airdrop
nargo compile
bb write_vk -b target/airdrop.json -o target/vk
bb contract -b target/airdrop.json -o ../../contracts/verifier.sol
cd ../..

# Deploy verifier
forge create contracts/verifier.sol:UltraVerifier \
  --private-key $YOUR_PRIVATE_KEY

# Deploy airdrop contract
forge create contracts/Airdrop.sol:Airdrop \
  --constructor-args \
  $TOKEN_ADDRESS \
  $VERIFIER_ADDRESS \
  $(cat merkle_root.txt) \
  --private-key $YOUR_PRIVATE_KEY
```

## Step 4: Generate a Claim

Users can generate their claim proof locally:

```bash
# Generate claim with Merkle proof
./cli/airdrop-cli/target/release/claim \
  --tree merkle_tree.txt \
  --index-map index_map.txt \
  --private-key YOUR_PRIVATE_KEY_HERE \
  --recipient 0xYourWalletAddress \
  --root $(cat merkle_root.txt) \
  --output claim.json
```

Output `claim.json`:
```json
{
  "merkle_root": "0x...",
  "recipient": "0x...",
  "nullifier": "0x...",
  "merkle_proof": ["0x...", "0x...", ...],
  "private_key_field": "0x...",
  "leaf_index": 0,
  "claimer_address": "0x..."
}
```

## Step 5: Generate Noir Proof

```bash
./cli/airdrop-cli/target/release/prove \
  --input claim.json \
  --circuit circuits/airdrop \
  --output proof.json
```

## Step 6: Submit to Contract

```bash
cast send $AIRDROP_ADDRESS \
  "claim(uint256[],bytes32,address)" \
  "[0xproof1,0xproof2,...]" \
  "0xnullifier..." \
  "0xrecipient..." \
  --private-key $YOUR_PRIVATE_KEY
```

## Testing with Sample Data

Use the provided sample accounts for testing:

```bash
# Build sample tree
./cli/airdrop-cli/target/release/build-tree \
  --input sample_accounts.txt \
  --root-output sample_root.txt \
  --index-output sample_index.txt \
  --tree-output sample_tree.txt

# Generate a test claim (replace with actual private key)
./cli/airdrop-cli/target/release/claim \
  --tree sample_tree.txt \
  --index-map sample_index.txt \
  --private-key YOUR_TEST_PRIVATE_KEY \
  --recipient 0xTestRecipient \
  --root $(cat sample_root.txt) \
  --output test_claim.json
```

## Troubleshooting

### Build Tree Fails

If you get "invalid address format" errors:
- Ensure addresses are valid 40-character hex strings
- Addresses can optionally have "0x" prefix

### Private Key Issues

Private key should be:
- 64 hex characters
- Can optionally have "0x" prefix

Example: `0x1234567890abcdef...` or `1234567890abcdef...`

### Memory Issues with Large Files

For very large account files (millions of addresses):
```bash
# Process in chunks
split -l 1000000 accounts.txt accounts_chunk_
for chunk in accounts_chunk_*; do
  ./build-tree --input $chunk --root-output ${chunk}_root.txt ...
done
# Then combine roots
```

## Security Notes

1. **Private Keys**: Never share private keys. The CLI only uses them locally.
2. **Nullifiers**: Each address can only claim once due to deterministic nullifiers.
3. **Merkle Root**: Once deployed to the contract, it cannot be changed (except by owner).