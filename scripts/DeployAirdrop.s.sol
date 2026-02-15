// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/Airdrop.sol";

/// @title Airdrop Deployment Script
/// @notice Deploys the Airdrop contract with the specified parameters
/// @dev Uses forge-std Script base contract. Requires PRIVATE_KEY environment variable.
contract DeployAirdrop is Script {
    error InvalidTokenAddress();
    error InvalidVerifierAddress();
    error InvalidMerkleRoot();
    error InvalidMaxClaims();

    /// @notice Deploys the Airdrop contract
    /// @param tokenAddress The ERC20 token address to distribute
    /// @param verifierAddress The Noir UltraVerifier contract address
    /// @param merkleRoot The root of the Merkle tree containing qualified addresses
    /// @param maxClaims Maximum number of claims allowed
    function run(
        address tokenAddress,
        address verifierAddress,
        bytes32 merkleRoot,
        uint256 maxClaims
    ) external {
        if (tokenAddress == address(0)) revert InvalidTokenAddress();
        if (verifierAddress == address(0)) revert InvalidVerifierAddress();
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (maxClaims == 0) revert InvalidMaxClaims();

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        Airdrop airdrop = new Airdrop(
            tokenAddress,
            verifierAddress,
            merkleRoot,
            maxClaims
        );

        vm.stopBroadcast();

        console.log("=== Deployment Summary ===");
        console.log("Airdrop contract:", address(airdrop));
        console.log("Token address:", tokenAddress);
        console.log("Verifier address:", verifierAddress);
        console.log("Merkle root:", vm.toString(merkleRoot));
        console.log("Max claims:", maxClaims);
        console.log("Deployer:", deployer);
    }
}