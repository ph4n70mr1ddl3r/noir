// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/Airdrop.sol";

contract DeployAirdrop is Script {
    function run(
        address tokenAddress,
        address verifierAddress,
        bytes32 merkleRoot,
        uint256 maxClaims
    ) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        Airdrop airdrop = new Airdrop(
            tokenAddress,
            verifierAddress,
            merkleRoot,
            maxClaims
        );

        vm.stopBroadcast();

        console.log("Airdrop contract deployed at:", address(airdrop));
    }
}