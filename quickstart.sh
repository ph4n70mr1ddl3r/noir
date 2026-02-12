#!/bin/bash

set -e

echo "=== Noir ZK Airdrop Quickstart ==="
echo ""

echo "Step 1: Installing Noir toolchain..."
if ! command -v nargo &> /dev/null; then
    curl -L https://raw.githubusercontent.com/noir-lang/noir/main/install_nargo.sh | bash
    export PATH="$HOME/.nargo/bin:$PATH"
else
    echo "Nargo already installed"
fi

echo ""
echo "Step 2: Compiling Noir circuit..."
cd circuits/airdrop
nargo compile
echo "Noir circuit compiled successfully"

echo ""
echo "Step 3: Building Rust CLI tools..."
cd ../../cli/airdrop-cli
cargo build --release
echo "CLI tools built successfully"

echo ""
echo "Step 4: Building sample Merkle tree..."
cd ../..
./cli/airdrop-cli/target/release/build-tree \
  --input sample_accounts.txt \
  --root-output merkle_root.txt \
  --index-output index_map.txt \
  --tree-output merkle_tree.txt

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "Next steps:"
echo "1. Review merkle_root.txt - this is your Merkle root"
echo "2. Deploy the smart contract with this root"
echo "3. Use the CLI tools to generate and submit proofs"
echo ""
echo "See README.md for detailed usage instructions"