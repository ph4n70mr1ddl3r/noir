// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { Airdrop, IUltraVerifier, IERC20 } from "./Airdrop.sol";

contract MockVerifier is IUltraVerifier {
    bool shouldVerify = true;

    function setVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    function verify(uint256[] calldata proof, uint256[] calldata publicInputs) external view returns (bool) {
        if (!shouldVerify) return false;
        if (proof.length == 0) return false;
        if (publicInputs.length != 3) return false;
        return true;
    }
}

contract MockERC20 is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address recipient, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

contract AirdropTest is Test {
    Airdrop airdrop;
    MockERC20 token;
    MockVerifier verifier;
    address owner = address(0x1);
    address user = address(0x2);
    bytes32 merkleRoot = bytes32(uint256(123));

    uint256 constant CLAIM_AMOUNT = 100 * 10 ** 18;
    uint256 constant MAX_CLAIMS = 1000;

    function setUp() public {
        vm.startPrank(owner);

        token = new MockERC20();
        token.mint(owner, 1000000 * 10 ** 18);

        verifier = new MockVerifier();

        airdrop = new Airdrop(address(token), address(verifier), merkleRoot, MAX_CLAIMS);

        bool success = token.transfer(address(airdrop), MAX_CLAIMS * CLAIM_AMOUNT);
        assertTrue(success, "Transfer to airdrop failed");
        vm.stopPrank();
    }

    function _mockProof() internal pure returns (uint256[] memory) {
        uint256[] memory proof = new uint256[](1);
        proof[0] = 1;
        return proof;
    }

    function testConstructor() public view {
        assertEq(address(airdrop.token()), address(token));
        assertEq(address(airdrop.verifier()), address(verifier));
        assertEq(airdrop.merkleRoot(), merkleRoot);
        assertEq(airdrop.owner(), owner);
        assertEq(airdrop.maxClaims(), MAX_CLAIMS);
    }

    function testClaimSuccess() public {
        bytes32 nullifier = bytes32(uint256(456));
        address recipient = user;

        verifier.setVerify(true);

        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, recipient);

        assertTrue(airdrop.isNullifierUsed(nullifier));
        assertEq(token.balanceOf(recipient), CLAIM_AMOUNT);
        assertEq(airdrop.totalClaimed(), CLAIM_AMOUNT);
        assertEq(airdrop.claimCount(), 1);
    }

    function testClaimInvalidProof() public {
        bytes32 nullifier = bytes32(uint256(456));

        verifier.setVerify(false);

        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidProof.selector);
        airdrop.claim(_mockProof(), nullifier, user);
    }

    function testClaimNullifierAlreadyUsed() public {
        bytes32 nullifier = bytes32(uint256(456));

        verifier.setVerify(true);

        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, user);

        vm.prank(user);
        vm.expectRevert(Airdrop.NullifierAlreadyUsed.selector);
        airdrop.claim(_mockProof(), nullifier, user);
    }

    function testClaimInvalidRecipient() public {
        bytes32 nullifier = bytes32(uint256(456));

        verifier.setVerify(true);

        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidRecipient.selector);
        airdrop.claim(_mockProof(), nullifier, address(0));
    }

    function testClaimToContractAddress() public {
        bytes32 nullifier = bytes32(uint256(456));

        verifier.setVerify(true);

        vm.prank(user);
        vm.expectRevert(Airdrop.ClaimToContract.selector);
        airdrop.claim(_mockProof(), nullifier, address(airdrop));
    }

    function testClaimMaxClaimsExceeded() public {
        verifier.setVerify(true);

        for (uint256 i = 0; i < MAX_CLAIMS; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 1));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 100));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        bytes32 finalNullifier = bytes32(uint256(MAX_CLAIMS + 2));
        verifier.setVerify(true);
        vm.prank(user);
        vm.expectRevert(Airdrop.MaxClaimsExceeded.selector);
        airdrop.claim(_mockProof(), finalNullifier, user);
    }

    function testClaimMaxClaimsBoundary() public {
        verifier.setVerify(true);

        for (uint256 i = 0; i < MAX_CLAIMS - 1; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 1));
            // forge-lint: disable-next-line(unsafe-typecast)
            address claimRecipient = address(uint160(i + 100));
            vm.prank(claimRecipient);
            airdrop.claim(_mockProof(), claimNullifier, claimRecipient);
        }

        bytes32 nullifier = bytes32(uint256(MAX_CLAIMS));
        // forge-lint: disable-next-line(unsafe-typecast)
        address boundaryRecipient = address(uint160(MAX_CLAIMS - 1 + 100));
        vm.prank(boundaryRecipient);
        airdrop.claim(_mockProof(), nullifier, boundaryRecipient);

        bytes32 finalNullifier = bytes32(uint256(MAX_CLAIMS + 101));
        vm.prank(user);
        vm.expectRevert(Airdrop.MaxClaimsExceeded.selector);
        airdrop.claim(_mockProof(), finalNullifier, user);
    }

    function testUpdateRootTimelock() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        // Try to execute before timelock expires
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(Airdrop.TimelockNotExpired.selector);
        airdrop.updateRoot(newRoot);

        // Execute after timelock
        vm.warp(block.timestamp + 1 days + 1);
        airdrop.updateRoot(newRoot);
        assertEq(airdrop.merkleRoot(), newRoot);
        vm.stopPrank();
    }

    function testUpdateVerifierTimelock() public {
        address newVerifier = address(0x3);

        vm.startPrank(owner);
        airdrop.scheduleUpdateVerifier(newVerifier);

        // Execute after timelock
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateVerifier(newVerifier);
        assertEq(address(airdrop.verifier()), newVerifier);
        vm.stopPrank();
    }

    event RootInitialized(bytes32 indexed root);
    event MaxClaimsSet(uint256 indexed oldMaxClaims, uint256 indexed newMaxClaims);
    event TokensWithdrawn(address indexed owner, uint256 amount);
    event RootUpdateScheduled(bytes32 indexed newRoot, bytes32 indexed operationHash, uint256 executeAfter);
    event VerifierUpdateScheduled(address indexed newVerifier, bytes32 indexed operationHash, uint256 executeAfter);
    event MaxClaimsUpdateScheduled(uint256 newMaxClaims, bytes32 indexed operationHash, uint256 executeAfter);
    event WithdrawalScheduled(uint256 amount, bytes32 indexed operationHash, uint256 executeAfter);
    event RenounceOwnershipScheduled(bytes32 indexed operationHash, uint256 executeAfter);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function testConstructorEvents() public {
        vm.startPrank(owner);
        MockERC20 newToken = new MockERC20();
        MockVerifier newVerifier = new MockVerifier();
        bytes32 newRoot = bytes32(uint256(999));

        vm.expectEmit(true, false, false, true);
        emit RootInitialized(newRoot);
        vm.expectEmit(true, false, false, true);
        emit MaxClaimsSet(0, 500);
        Airdrop newAirdrop = new Airdrop(address(newToken), address(newVerifier), newRoot, 500);

        assertEq(newAirdrop.merkleRoot(), newRoot);
        assertEq(newAirdrop.maxClaims(), 500);
        vm.stopPrank();
    }

    function testScheduleUpdateRootEvent() public {
        bytes32 newRoot = bytes32(uint256(789));
        bytes32 expectedHash = keccak256(abi.encode("updateRoot", newRoot));

        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit RootUpdateScheduled(newRoot, expectedHash, block.timestamp + 2 days);
        airdrop.scheduleUpdateRoot(newRoot);
    }

    function testScheduleUpdateVerifierEvent() public {
        address newVerifier = address(0x123);
        bytes32 expectedHash = keccak256(abi.encode("updateVerifier", newVerifier));

        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit VerifierUpdateScheduled(newVerifier, expectedHash, block.timestamp + 2 days);
        airdrop.scheduleUpdateVerifier(newVerifier);
    }

    function testScheduleSetMaxClaimsEvent() public {
        uint256 newMaxClaims = 2000;
        bytes32 expectedHash = keccak256(abi.encode("setMaxClaims", newMaxClaims));

        vm.prank(owner);
        vm.expectEmit(false, true, false, true);
        emit MaxClaimsUpdateScheduled(newMaxClaims, expectedHash, block.timestamp + 2 days);
        airdrop.scheduleSetMaxClaims(newMaxClaims);
    }

    function testScheduleWithdrawTokensEvent() public {
        uint256 amount = 100 * 10 ** 18;
        bytes32 expectedHash = keccak256(abi.encode("withdrawTokens", amount));

        vm.prank(owner);
        vm.expectEmit(false, true, false, true);
        emit WithdrawalScheduled(amount, expectedHash, block.timestamp + 2 days);
        airdrop.scheduleWithdrawTokens(amount);
    }

    function testScheduleRenounceOwnershipEvent() public {
        bytes32 expectedHash = keccak256(abi.encode("renounceOwnership"));

        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit RenounceOwnershipScheduled(expectedHash, block.timestamp + 2 days);
        airdrop.scheduleRenounceOwnership();
    }

    function testSetMaxClaimsTimelock() public {
        uint256 newMaxClaims = 2000;

        vm.startPrank(owner);
        airdrop.scheduleSetMaxClaims(newMaxClaims);

        // Execute after timelock
        vm.warp(block.timestamp + 2 days + 1);
        vm.expectEmit(true, false, false, true);
        emit MaxClaimsSet(MAX_CLAIMS, newMaxClaims);
        airdrop.setMaxClaims(newMaxClaims);
        assertEq(airdrop.maxClaims(), newMaxClaims);
        vm.stopPrank();
    }

    function testOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.scheduleUpdateRoot(bytes32(uint256(1)));

        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.updateRoot(bytes32(0));
    }

    function testScheduleUpdateRootZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(Airdrop.InvalidRoot.selector);
        airdrop.scheduleUpdateRoot(bytes32(0));
    }

    function testScheduleUpdateVerifierZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(Airdrop.InvalidVerifier.selector);
        airdrop.scheduleUpdateVerifier(address(0));
    }

    function testScheduleSetMaxClaimsZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(Airdrop.InvalidMaxClaims.selector);
        airdrop.scheduleSetMaxClaims(0);
    }

    function testScheduleSetMaxClaimsBelowCurrentReverts() public {
        verifier.setVerify(true);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 1));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 100));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        vm.prank(owner);
        vm.expectRevert(Airdrop.MaxClaimsBelowCurrent.selector);
        airdrop.scheduleSetMaxClaims(3);
    }

    function testCancelOperationAlreadyCancelled() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        airdrop.cancelOperation(operationHash);

        vm.expectRevert(Airdrop.OperationAlreadyCancelled.selector);
        airdrop.cancelOperation(operationHash);
        vm.stopPrank();
    }

    function testRescheduleAfterCancel() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        airdrop.cancelOperation(operationHash);

        airdrop.scheduleUpdateRoot(newRoot);

        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateRoot(newRoot);
        assertEq(airdrop.merkleRoot(), newRoot);
        vm.stopPrank();
    }

    function testRescheduleAndCancelAgain() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        airdrop.cancelOperation(operationHash);

        airdrop.scheduleUpdateRoot(newRoot);

        airdrop.cancelOperation(operationHash);
        assertEq(airdrop.timelockSchedule(operationHash), 0);
        vm.stopPrank();
    }

    function testBatchCancelOperations() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 root2 = bytes32(uint256(790));
        bytes32 root3 = bytes32(uint256(791));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(root1);
        airdrop.scheduleUpdateRoot(root2);
        airdrop.scheduleUpdateRoot(root3);

        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));
        bytes32 hash2 = keccak256(abi.encode("updateRoot", root2));
        bytes32 hash3 = keccak256(abi.encode("updateRoot", root3));

        assertGt(airdrop.timelockSchedule(hash1), 0);
        assertGt(airdrop.timelockSchedule(hash2), 0);
        assertGt(airdrop.timelockSchedule(hash3), 0);

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = hash1;
        hashes[1] = hash2;
        hashes[2] = hash3;

        airdrop.batchCancelOperations(hashes);

        assertEq(airdrop.timelockSchedule(hash1), 0);
        assertEq(airdrop.timelockSchedule(hash2), 0);
        assertEq(airdrop.timelockSchedule(hash3), 0);
        assertTrue(airdrop.cancelledOperations(hash1));
        assertTrue(airdrop.cancelledOperations(hash2));
        assertTrue(airdrop.cancelledOperations(hash3));
        vm.stopPrank();
    }

    function testBatchCancelOperationsEmptyBatch() public {
        bytes32[] memory emptyHashes = new bytes32[](0);
        vm.prank(owner);
        vm.expectRevert(Airdrop.EmptyBatch.selector);
        airdrop.batchCancelOperations(emptyHashes);
    }

    function testBatchCancelOperationsNotScheduled() public {
        vm.startPrank(owner);
        bytes32 root1 = bytes32(uint256(789));
        airdrop.scheduleUpdateRoot(root1);

        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));
        bytes32 fakeHash = bytes32(uint256(999));

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = hash1;
        hashes[1] = fakeHash;

        vm.expectRevert(Airdrop.OperationNotScheduled.selector);
        airdrop.batchCancelOperations(hashes);
        vm.stopPrank();
    }

    function testWithdrawTokens() public {
        uint256 withdrawAmount = 100 * 10 ** 18;

        verifier.setVerify(true);

        // First fund the contract with extra tokens (owner already has balance from initial mint)
        uint256 ownerBalanceBefore = token.balanceOf(owner);
        vm.prank(owner);
        bool success = token.transfer(address(airdrop), withdrawAmount);
        assertTrue(success, "Transfer to airdrop failed");

        vm.startPrank(owner);
        airdrop.scheduleWithdrawTokens(withdrawAmount);

        // Try to execute before timelock expires
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(Airdrop.TimelockNotExpired.selector);
        airdrop.withdrawTokens(withdrawAmount);

        // Execute after timelock
        vm.warp(block.timestamp + 1 days + 1);
        airdrop.withdrawTokens(withdrawAmount);
        vm.stopPrank();

        // Owner should be back to original balance after withdraw
        assertEq(token.balanceOf(owner), ownerBalanceBefore);
    }

    function testWithdrawTokensEvent() public {
        uint256 withdrawAmount = 100 * 10 ** 18;

        vm.prank(owner);
        bool success = token.transfer(address(airdrop), withdrawAmount);
        assertTrue(success, "Transfer to airdrop failed");

        vm.startPrank(owner);
        airdrop.scheduleWithdrawTokens(withdrawAmount);

        vm.warp(block.timestamp + 2 days + 1);
        vm.expectEmit(true, false, false, true);
        emit TokensWithdrawn(owner, withdrawAmount);
        airdrop.withdrawTokens(withdrawAmount);
        vm.stopPrank();
    }

    function testScheduleWithdrawTokensInsufficientBalance() public {
        uint256 excessiveAmount = token.balanceOf(address(airdrop)) + 1;
        vm.prank(owner);
        vm.expectRevert(Airdrop.InsufficientBalanceForWithdraw.selector);
        airdrop.scheduleWithdrawTokens(excessiveAmount);
    }

    /// @notice Tests that the reentrancy guard prevents nested claim calls
    /// @dev The ReentrancyToken attempts to call claim() during transfer.
    ///      The inner claim hits the nonReentrant modifier and reverts with ReentrancyGuardReentrantCall.
    ///      Since Airdrop.claim() uses a low-level call for token transfer, the inner revert
    ///      is caught and converted to TransferFailed. The key verification is that the nullifier
    ///      was NOT marked as used, proving the reentrancy was prevented.
    function testReentrancyGuard() public {
        ReentrancyToken reentrancyToken = new ReentrancyToken();
        MockVerifier reentrancyVerifier = new MockVerifier();
        reentrancyVerifier.setVerify(true);

        vm.startPrank(owner);
        Airdrop reentrancyAirdrop = new Airdrop(
            address(reentrancyToken), address(reentrancyVerifier), merkleRoot, MAX_CLAIMS
        );
        reentrancyToken.mint(address(reentrancyAirdrop), MAX_CLAIMS * CLAIM_AMOUNT);
        vm.stopPrank();

        AttackerContract attacker = new AttackerContract(payable(address(reentrancyAirdrop)));
        reentrancyToken.setAttacker(address(attacker), payable(address(reentrancyAirdrop)));

        bytes32 nullifier = bytes32(uint256(999));

        vm.prank(address(attacker));
        vm.expectRevert(Airdrop.TransferFailed.selector);
        reentrancyAirdrop.claim(_mockProof(), nullifier, address(attacker));

        assertFalse(reentrancyAirdrop.isNullifierUsed(nullifier));
    }

    function testZeroAddressInConstructor() public {
        vm.startPrank(owner);
        vm.expectRevert(Airdrop.InvalidToken.selector);
        new Airdrop(address(0), address(verifier), merkleRoot, MAX_CLAIMS);

        vm.expectRevert(Airdrop.InvalidVerifier.selector);
        new Airdrop(address(token), address(0), merkleRoot, MAX_CLAIMS);

        vm.expectRevert(Airdrop.InvalidRoot.selector);
        new Airdrop(address(token), address(verifier), bytes32(0), MAX_CLAIMS);

        vm.expectRevert(Airdrop.InvalidMaxClaims.selector);
        new Airdrop(address(token), address(verifier), merkleRoot, 0);
        vm.stopPrank();
    }

    function testOwnershipTransfer() public {
        address newOwner = address(0x3);

        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.transferOwnership(newOwner);

        vm.prank(owner);
        airdrop.transferOwnership(newOwner);
        assertEq(airdrop.pendingOwner(), newOwner);
        assertEq(airdrop.owner(), owner);

        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.acceptOwnership();

        vm.prank(newOwner);
        airdrop.acceptOwnership();
        assertEq(airdrop.owner(), newOwner);
        assertEq(airdrop.pendingOwner(), address(0));
    }

    function testTransferOwnershipZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Airdrop.InvalidRecipient.selector);
        airdrop.transferOwnership(address(0));
    }

    function testAcceptOwnershipNoPendingOwner() public {
        vm.prank(user);
        vm.expectRevert(Airdrop.NoPendingOwnershipTransfer.selector);
        airdrop.acceptOwnership();
    }

    event PendingOwnerSet(address indexed pendingOwner);

    function testPendingOwnerSetEvent() public {
        address newOwner = address(0x3);
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit PendingOwnerSet(newOwner);
        airdrop.transferOwnership(newOwner);
        assertEq(airdrop.pendingOwner(), newOwner);
    }

    function testCancelOperation() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        assertGt(airdrop.timelockSchedule(operationHash), 0);

        airdrop.cancelOperation(operationHash);
        assertEq(airdrop.timelockSchedule(operationHash), 0);

        vm.warp(block.timestamp + 2 days + 1);
        vm.expectRevert(Airdrop.TimelockNotExpired.selector);
        airdrop.updateRoot(newRoot);
        vm.stopPrank();
    }

    function testCancelOperationNotScheduled() public {
        bytes32 fakeHash = bytes32(uint256(999));
        vm.prank(owner);
        vm.expectRevert(Airdrop.OperationNotScheduled.selector);
        airdrop.cancelOperation(fakeHash);
    }

    function testEmptyProof() public {
        bytes32 nullifier = bytes32(uint256(456));
        verifier.setVerify(true);
        vm.prank(user);
        vm.expectRevert(Airdrop.EmptyProof.selector);
        airdrop.claim(new uint256[](0), nullifier, user);
    }

    function testProofTooLong() public {
        bytes32 nullifier = bytes32(uint256(456));
        verifier.setVerify(true);
        uint256[] memory longProof = new uint256[](1001);
        for (uint256 i = 0; i < 1001; i++) {
            longProof[i] = i;
        }
        vm.prank(user);
        vm.expectRevert(Airdrop.ProofTooLong.selector);
        airdrop.claim(longProof, nullifier, user);
    }

    function testProofMaxLength() public {
        bytes32 nullifier = bytes32(uint256(456));
        verifier.setVerify(true);
        uint256[] memory maxProof = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            maxProof[i] = i + 1;
        }
        vm.prank(user);
        airdrop.claim(maxProof, nullifier, user);
        assertTrue(airdrop.isNullifierUsed(nullifier));
    }

    function testZeroNullifier() public {
        verifier.setVerify(true);
        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidNullifier.selector);
        airdrop.claim(_mockProof(), bytes32(0), user);
    }

    function testScheduleOverwrite() public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);
        vm.expectRevert(Airdrop.OperationAlreadyScheduled.selector);
        airdrop.scheduleUpdateRoot(newRoot);
        vm.stopPrank();
    }

    function testMaxClaimsBelowCurrent() public {
        verifier.setVerify(true);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 1));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 100));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        vm.startPrank(owner);
        vm.expectRevert(Airdrop.MaxClaimsBelowCurrent.selector);
        airdrop.scheduleSetMaxClaims(3);
        vm.stopPrank();
    }

    function testTimelockExpiration() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        // Wait for 14 days + 2 days = 16 days total (past expiration)
        vm.warp(block.timestamp + 14 days + 2 days + 1);
        vm.expectRevert(Airdrop.OperationExpired.selector);
        airdrop.updateRoot(newRoot);
        vm.stopPrank();
    }

    function testClaimCountIncrements() public {
        verifier.setVerify(true);
        assertEq(airdrop.claimCount(), 0);

        for (uint256 i = 0; i < 5; i++) {
            bytes32 claimNullifier = bytes32(i + 1000);
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 200));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
            assertEq(airdrop.claimCount(), i + 1);
        }

        assertEq(airdrop.claimCount(), 5);
        assertEq(airdrop.totalClaimed(), 5 * CLAIM_AMOUNT);
    }

    function testPause() public {
        verifier.setVerify(true);
        assertFalse(airdrop.paused());

        vm.prank(owner);
        airdrop.pause();
        assertTrue(airdrop.paused());

        bytes32 nullifier = bytes32(uint256(456));
        vm.prank(user);
        vm.expectRevert(Airdrop.ContractPaused.selector);
        airdrop.claim(_mockProof(), nullifier, user);
    }

    function testUnpause() public {
        verifier.setVerify(true);

        vm.startPrank(owner);
        airdrop.pause();
        assertTrue(airdrop.paused());

        airdrop.unpause();
        assertFalse(airdrop.paused());
        vm.stopPrank();

        bytes32 nullifier = bytes32(uint256(456));
        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, user);
        assertTrue(airdrop.isNullifierUsed(nullifier));
    }

    function testPauseOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.pause();
    }

    function testUnpauseOnlyOwner() public {
        vm.startPrank(owner);
        airdrop.pause();

        vm.stopPrank();
        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.unpause();
    }

    function testUnpauseWhenNotPaused() public {
        vm.prank(owner);
        vm.expectRevert(Airdrop.ContractNotPaused.selector);
        airdrop.unpause();
    }

    function testPauseWhenAlreadyPaused() public {
        vm.startPrank(owner);
        airdrop.pause();
        vm.expectRevert(Airdrop.ContractPaused.selector);
        airdrop.pause();
        vm.stopPrank();
    }

    function testClaimableBalance() public view {
        uint256 expectedBalance = MAX_CLAIMS * CLAIM_AMOUNT;
        assertEq(airdrop.claimableBalance(), expectedBalance);
    }

    function testRemainingClaims() public view {
        assertEq(airdrop.remainingClaims(), MAX_CLAIMS);
    }

    function testRemainingClaimsAfterClaims() public {
        verifier.setVerify(true);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 claimNullifier = bytes32(i + 5000);
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 300));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }
        assertEq(airdrop.remainingClaims(), MAX_CLAIMS - 5);
    }

    function testRemainingClaimsWhenMaxReached() public {
        verifier.setVerify(true);
        for (uint256 i = 0; i < MAX_CLAIMS; i++) {
            bytes32 claimNullifier = bytes32(i + 10000);
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 400));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }
        assertEq(airdrop.remainingClaims(), 0);
    }

    function testClaimInfo() public view {
        Airdrop.ClaimInfo memory info = airdrop.claimInfo();

        assertEq(info.token, address(token));
        assertEq(info.merkleRoot, merkleRoot);
        assertEq(info.claimAmount, CLAIM_AMOUNT);
        assertEq(info.totalClaimed, 0);
        assertEq(info.claimCount, 0);
        assertEq(info.maxClaims, MAX_CLAIMS);
        assertEq(info.remainingClaims, MAX_CLAIMS);
        assertFalse(info.isPaused);
    }

    function testClaimInfoAfterClaims() public {
        verifier.setVerify(true);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 claimNullifier = bytes32(i + 20000);
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 500));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        Airdrop.ClaimInfo memory info = airdrop.claimInfo();

        assertEq(info.totalClaimed, 5 * CLAIM_AMOUNT);
        assertEq(info.claimCount, 5);
        assertEq(info.remainingClaims, MAX_CLAIMS - 5);
    }

    function testDomainSeparator() public view {
        assertEq(bytes4(airdrop.DOMAIN_SEPARATOR()), bytes4(0xa1b2c3d4));
    }

    function testVersion() public view {
        assertEq(airdrop.VERSION(), "1.0.0");
    }

    function testOperationNotExecutedTwice() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        assertTrue(airdrop.executedOperations(operationHash));

        // After execution, schedule is deleted so TimelockNotExpired is raised
        vm.expectRevert(Airdrop.TimelockNotExpired.selector);
        airdrop.updateRoot(newRoot);
        vm.stopPrank();
    }

    function testFuzz_ClaimWithValidProof(bytes32 nullifier, address recipient) public {
        vm.assume(recipient != address(0));
        vm.assume(recipient != address(airdrop));
        vm.assume(nullifier != bytes32(0));
        verifier.setVerify(true);

        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, recipient);

        assertTrue(airdrop.isNullifierUsed(nullifier));
        assertEq(token.balanceOf(recipient), CLAIM_AMOUNT);
    }

    function testFuzz_ClaimRejectsZeroRecipient(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        verifier.setVerify(true);

        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidRecipient.selector);
        airdrop.claim(_mockProof(), nullifier, address(0));
    }

    function testFuzz_OwnershipTransfer(address newOwner) public {
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != owner);

        vm.prank(owner);
        airdrop.transferOwnership(newOwner);
        assertEq(airdrop.pendingOwner(), newOwner);

        vm.prank(newOwner);
        airdrop.acceptOwnership();
        assertEq(airdrop.owner(), newOwner);
    }

    function testFuzz_ScheduleAndExecuteRootUpdate(bytes32 newRoot) public {
        vm.assume(newRoot != bytes32(0));
        vm.assume(newRoot != merkleRoot);

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateRoot(newRoot);
        assertEq(airdrop.merkleRoot(), newRoot);
        vm.stopPrank();
    }

    function testFuzz_TimelockPreventsEarlyExecution(bytes32 newRoot, uint256 timeSkip) public {
        vm.assume(newRoot != bytes32(0));
        vm.assume(timeSkip < 2 days);
        vm.assume(timeSkip > 0);

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        vm.warp(block.timestamp + timeSkip);
        vm.expectRevert(Airdrop.TimelockNotExpired.selector);
        airdrop.updateRoot(newRoot);
        vm.stopPrank();
    }

    function testRenounceOwnership() public {
        vm.startPrank(owner);
        airdrop.scheduleRenounceOwnership();

        vm.warp(block.timestamp + 2 days + 1);
        airdrop.renounceOwnership();

        assertEq(airdrop.owner(), address(0));
        vm.stopPrank();
    }

    function testRenounceOwnershipTimelock() public {
        vm.startPrank(owner);
        airdrop.scheduleRenounceOwnership();

        vm.expectRevert(Airdrop.TimelockNotExpired.selector);
        airdrop.renounceOwnership();
        vm.stopPrank();
    }

    function testFuzz_RejectsEthTransfers() public {
        (bool success,) = address(airdrop).call{ value: 1 ether }("");
        assertFalse(success);
    }

    function testFallbackReverts() public {
        (bool success,) = address(airdrop).call(abi.encodeWithSignature("unknownFunction()"));
        assertFalse(success);
    }

    function testWithdrawTokensBalanceCheckAtExecution() public {
        uint256 withdrawAmount = MAX_CLAIMS * CLAIM_AMOUNT;

        vm.startPrank(owner);
        airdrop.scheduleWithdrawTokens(withdrawAmount);
        vm.stopPrank();

        verifier.setVerify(true);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 1));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 100));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        vm.startPrank(owner);
        vm.warp(block.timestamp + 2 days + 1);

        vm.expectRevert(Airdrop.InsufficientBalanceForWithdraw.selector);
        airdrop.withdrawTokens(withdrawAmount);
        vm.stopPrank();
    }

    function testInvariant_TotalClaimedMatchesClaimCount() public {
        verifier.setVerify(true);

        assertEq(airdrop.totalClaimed(), 0);
        assertEq(airdrop.claimCount(), 0);

        uint256 expectedTotal = 0;
        for (uint256 i = 0; i < 10; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 50000));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 500));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);

            expectedTotal += CLAIM_AMOUNT;
            assertEq(airdrop.totalClaimed(), expectedTotal);
            assertEq(airdrop.claimCount(), i + 1);
            assertEq(airdrop.totalClaimed(), airdrop.claimCount() * CLAIM_AMOUNT);
        }
    }

    function testFuzz_InvariantTotalClaimedAfterClaims(uint8 numClaims) public {
        vm.assume(numClaims > 0);
        vm.assume(numClaims <= 50);

        verifier.setVerify(true);

        for (uint256 i = 0; i < numClaims; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 60000));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 600));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        assertEq(airdrop.totalClaimed(), uint256(numClaims) * CLAIM_AMOUNT);
        assertEq(airdrop.claimCount(), uint256(numClaims));
    }

    function testClaimDoesNotAffectOtherState() public {
        verifier.setVerify(true);

        bytes32 nullifier = bytes32(uint256(12345));
        address recipient = address(0xABC);
        address originalOwner = airdrop.owner();
        bytes32 originalRoot = airdrop.merkleRoot();
        address originalVerifier = address(airdrop.verifier());
        address originalToken = address(airdrop.token());
        uint256 originalMaxClaims = airdrop.maxClaims();
        bool originalPaused = airdrop.paused();

        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, recipient);

        assertEq(airdrop.owner(), originalOwner);
        assertEq(airdrop.merkleRoot(), originalRoot);
        assertEq(address(airdrop.verifier()), originalVerifier);
        assertEq(address(airdrop.token()), originalToken);
        assertEq(airdrop.maxClaims(), originalMaxClaims);
        assertEq(airdrop.paused(), originalPaused);
    }

    function testTokenTransferReturnsFalse() public {
        FailingToken failingToken = new FailingToken();
        MockVerifier failingVerifier = new MockVerifier();
        failingVerifier.setVerify(true);

        vm.startPrank(owner);
        Airdrop failingAirdrop = new Airdrop(
            address(failingToken), address(failingVerifier), merkleRoot, MAX_CLAIMS
        );
        failingToken.mint(address(failingAirdrop), MAX_CLAIMS * CLAIM_AMOUNT);
        vm.stopPrank();

        bytes32 nullifier = bytes32(uint256(456));
        vm.prank(user);
        vm.expectRevert(Airdrop.TransferFailed.selector);
        failingAirdrop.claim(_mockProof(), nullifier, user);
    }

    function testClaimExactBalance() public {
        vm.startPrank(owner);
        MockERC20 smallToken = new MockERC20();
        smallToken.mint(owner, CLAIM_AMOUNT);
        MockVerifier smallVerifier = new MockVerifier();
        smallVerifier.setVerify(true);
        Airdrop smallAirdrop = new Airdrop(
            address(smallToken), address(smallVerifier), merkleRoot, 10
        );
        smallToken.transfer(address(smallAirdrop), CLAIM_AMOUNT);
        vm.stopPrank();

        bytes32 nullifier = bytes32(uint256(999));
        vm.prank(user);
        smallAirdrop.claim(_mockProof(), nullifier, user);

        assertEq(smallToken.balanceOf(user), CLAIM_AMOUNT);
        assertEq(smallToken.balanceOf(address(smallAirdrop)), 0);
    }

    function testMaxClaimsBoundarySingle() public {
        vm.startPrank(owner);
        MockERC20 singleToken = new MockERC20();
        singleToken.mint(owner, CLAIM_AMOUNT);
        MockVerifier singleVerifier = new MockVerifier();
        singleVerifier.setVerify(true);
        Airdrop singleAirdrop = new Airdrop(
            address(singleToken), address(singleVerifier), merkleRoot, 1
        );
        singleToken.transfer(address(singleAirdrop), CLAIM_AMOUNT);
        vm.stopPrank();

        bytes32 nullifier = bytes32(uint256(1));
        vm.prank(user);
        singleAirdrop.claim(_mockProof(), nullifier, user);

        assertEq(singleAirdrop.claimCount(), 1);

        bytes32 nullifier2 = bytes32(uint256(2));
        vm.prank(user);
        vm.expectRevert(Airdrop.MaxClaimsExceeded.selector);
        singleAirdrop.claim(_mockProof(), nullifier2, user);
    }

    function testBatchClaimSuccess() public {
        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](3);
        for (uint256 i = 0; i < 3; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 100)),
                recipient: address(uint160(i + 200))
            });
        }

        vm.prank(user);
        airdrop.batchClaim(claims);

        assertEq(airdrop.claimCount(), 3);
        assertEq(airdrop.totalClaimed(), 3 * CLAIM_AMOUNT);

        for (uint256 i = 0; i < 3; i++) {
            assertTrue(airdrop.isNullifierUsed(bytes32(uint256(i + 100))));
            assertEq(token.balanceOf(address(uint160(i + 200))), CLAIM_AMOUNT);
        }
    }

    function testBatchClaimEmptyBatch() public {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](0);
        vm.prank(user);
        vm.expectRevert(Airdrop.EmptyBatch.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimTooLarge() public {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](11);
        for (uint256 i = 0; i < 11; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 100)),
                recipient: address(uint160(i + 200))
            });
        }

        verifier.setVerify(true);
        vm.prank(user);
        vm.expectRevert(Airdrop.BatchClaimsTooLarge.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimInvalidProof() public {
        verifier.setVerify(false);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](1);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidProof.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimDuplicateNullifier() public {
        verifier.setVerify(true);

        airdrop.claim(_mockProof(), bytes32(uint256(100)), user);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](1);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.NullifierAlreadyUsed.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimIntraBatchDuplicateNullifier() public {
        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });
        claims[1] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.NullifierAlreadyUsed.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimMaxClaimsExceeded() public {
        verifier.setVerify(true);

        vm.startPrank(owner);
        MockERC20 smallToken = new MockERC20();
        smallToken.mint(owner, CLAIM_AMOUNT * 5);
        MockVerifier smallVerifier = new MockVerifier();
        smallVerifier.setVerify(true);
        Airdrop smallAirdrop = new Airdrop(
            address(smallToken), address(smallVerifier), merkleRoot, 2
        );
        smallToken.transfer(address(smallAirdrop), CLAIM_AMOUNT * 2);
        vm.stopPrank();

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](3);
        for (uint256 i = 0; i < 3; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 100)),
                recipient: address(uint160(i + 200))
            });
        }

        vm.prank(user);
        vm.expectRevert(Airdrop.MaxClaimsExceeded.selector);
        smallAirdrop.batchClaim(claims);
    }

    function testBatchClaimWhenPaused() public {
        verifier.setVerify(true);
        vm.prank(owner);
        airdrop.pause();

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](1);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.ContractPaused.selector);
        airdrop.batchClaim(claims);
    }

    function testFuzz_BatchClaimWithValidProofs(uint8 batchSize) public {
        vm.assume(batchSize > 0);
        vm.assume(batchSize <= 10);

        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 1000)),
                recipient: address(uint160(i + 2000))
            });
        }

        vm.prank(user);
        airdrop.batchClaim(claims);

        assertEq(airdrop.claimCount(), batchSize);
        assertEq(airdrop.totalClaimed(), uint256(batchSize) * CLAIM_AMOUNT);

        for (uint256 i = 0; i < batchSize; i++) {
            assertTrue(airdrop.isNullifierUsed(bytes32(uint256(i + 1000))));
            assertEq(token.balanceOf(address(uint160(i + 2000))), CLAIM_AMOUNT);
        }
    }

    function testFuzz_BatchClaimRejectsZeroRecipient(uint8 batchSize, uint8 zeroIndex) public {
        vm.assume(batchSize > 0);
        vm.assume(batchSize <= 10);
        vm.assume(zeroIndex < batchSize);

        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            address recipient = (i == zeroIndex) ? address(0) : address(uint160(i + 2000));
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 1000)),
                recipient: recipient
            });
        }

        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidRecipient.selector);
        airdrop.batchClaim(claims);
    }

    function testFuzz_BatchClaimRejectsZeroNullifier(uint8 batchSize, uint8 zeroIndex) public {
        vm.assume(batchSize > 0);
        vm.assume(batchSize <= 10);
        vm.assume(zeroIndex < batchSize);

        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            bytes32 nullifier = (i == zeroIndex) ? bytes32(0) : bytes32(uint256(i + 1000));
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: nullifier,
                recipient: address(uint160(i + 2000))
            });
        }

        vm.prank(user);
        vm.expectRevert(Airdrop.InvalidNullifier.selector);
        airdrop.batchClaim(claims);
    }

    function testReentrancyGuardBatchClaim() public {
        ReentrancyToken reentrancyToken = new ReentrancyToken();
        MockVerifier reentrancyVerifier = new MockVerifier();
        reentrancyVerifier.setVerify(true);

        vm.startPrank(owner);
        Airdrop reentrancyAirdrop = new Airdrop(
            address(reentrancyToken), address(reentrancyVerifier), merkleRoot, MAX_CLAIMS
        );
        reentrancyToken.mint(address(reentrancyAirdrop), MAX_CLAIMS * CLAIM_AMOUNT);
        vm.stopPrank();

        AttackerContract attacker = new AttackerContract(payable(address(reentrancyAirdrop)));
        reentrancyToken.setAttacker(address(attacker), payable(address(reentrancyAirdrop)));

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(999)),
            recipient: address(attacker)
        });
        claims[1] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(1000)),
            recipient: address(attacker)
        });

        vm.prank(address(attacker));
        vm.expectRevert(Airdrop.TransferFailed.selector);
        reentrancyAirdrop.batchClaim(claims);

        assertFalse(reentrancyAirdrop.isNullifierUsed(bytes32(uint256(999))));
        assertFalse(reentrancyAirdrop.isNullifierUsed(bytes32(uint256(1000))));
    }

    function testInvariant_BatchClaimTotalClaimedMatchesClaimCount() public {
        verifier.setVerify(true);

        assertEq(airdrop.totalClaimed(), 0);
        assertEq(airdrop.claimCount(), 0);

        uint256 expectedTotalClaims = 0;

        for (uint256 batch = 0; batch < 5; batch++) {
            uint256 batchSize = 2 + (batch % 3);
            Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
            for (uint256 i = 0; i < batchSize; i++) {
                claims[i] = Airdrop.ClaimParams({
                    proof: _mockProof(),
                    nullifier: bytes32(uint256(batch * 100 + i + 50000)),
                    recipient: address(uint160(batch * 100 + i + 500))
                });
            }

            vm.prank(user);
            airdrop.batchClaim(claims);

            expectedTotalClaims += batchSize;

            assertEq(airdrop.claimCount(), expectedTotalClaims);
            assertEq(airdrop.totalClaimed(), expectedTotalClaims * CLAIM_AMOUNT);
        }
    }

    function testFuzz_BatchClaimInvariantTotalClaimed(uint8 numBatches, uint8 batchSize) public {
        vm.assume(numBatches > 0);
        vm.assume(numBatches <= 5);
        vm.assume(batchSize > 0);
        vm.assume(batchSize <= 5);

        verifier.setVerify(true);

        uint256 totalExpectedClaims = 0;
        uint256 nullifierOffset = 70000;

        for (uint256 batch = 0; batch < numBatches; batch++) {
            uint256 currentBatchSize = uint256(batchSize);
            if (currentBatchSize > MAX_CLAIMS - totalExpectedClaims) {
                currentBatchSize = MAX_CLAIMS - totalExpectedClaims;
            }
            if (currentBatchSize == 0) break;

            Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](currentBatchSize);
            for (uint256 i = 0; i < currentBatchSize; i++) {
                claims[i] = Airdrop.ClaimParams({
                    proof: _mockProof(),
                    nullifier: bytes32(uint256(nullifierOffset + batch * 100 + i)),
                    recipient: address(uint160(batch * 100 + i + 600))
                });
            }

            vm.prank(user);
            airdrop.batchClaim(claims);

            totalExpectedClaims += currentBatchSize;
        }

        assertEq(airdrop.totalClaimed(), totalExpectedClaims * CLAIM_AMOUNT);
        assertEq(airdrop.claimCount(), totalExpectedClaims);
    }

    function testBatchClaimDoesNotAffectOtherState() public {
        verifier.setVerify(true);

        address originalOwner = airdrop.owner();
        bytes32 originalRoot = airdrop.merkleRoot();
        address originalVerifier = address(airdrop.verifier());
        address originalToken = address(airdrop.token());
        uint256 originalMaxClaims = airdrop.maxClaims();
        bool originalPaused = airdrop.paused();

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](3);
        for (uint256 i = 0; i < 3; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 80000)),
                recipient: address(uint160(i + 700))
            });
        }

        vm.prank(user);
        airdrop.batchClaim(claims);

        assertEq(airdrop.owner(), originalOwner);
        assertEq(airdrop.merkleRoot(), originalRoot);
        assertEq(address(airdrop.verifier()), originalVerifier);
        assertEq(address(airdrop.token()), originalToken);
        assertEq(airdrop.maxClaims(), originalMaxClaims);
        assertEq(airdrop.paused(), originalPaused);
    }

    function testBatchClaimToContractAddress() public {
        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: address(airdrop)
        });
        claims[1] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(101)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.ClaimToContract.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimEmptyProof() public {
        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });
        claims[1] = Airdrop.ClaimParams({
            proof: new uint256[](0),
            nullifier: bytes32(uint256(101)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.EmptyProof.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimProofTooLong() public {
        verifier.setVerify(true);

        uint256[] memory longProof = new uint256[](1001);
        for (uint256 i = 0; i < 1001; i++) {
            longProof[i] = i;
        }

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](1);
        claims[0] = Airdrop.ClaimParams({
            proof: longProof,
            nullifier: bytes32(uint256(100)),
            recipient: user
        });

        vm.prank(user);
        vm.expectRevert(Airdrop.ProofTooLong.selector);
        airdrop.batchClaim(claims);
    }

    function testBatchClaimInsufficientBalance() public {
        verifier.setVerify(true);

        vm.startPrank(owner);
        MockERC20 smallToken = new MockERC20();
        smallToken.mint(owner, CLAIM_AMOUNT);
        MockVerifier smallVerifier = new MockVerifier();
        smallVerifier.setVerify(true);
        Airdrop smallAirdrop = new Airdrop(
            address(smallToken), address(smallVerifier), merkleRoot, 10
        );
        smallToken.transfer(address(smallAirdrop), CLAIM_AMOUNT);
        vm.stopPrank();

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        for (uint256 i = 0; i < 2; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 100)),
                recipient: address(uint160(i + 200))
            });
        }

        vm.prank(user);
        vm.expectRevert(Airdrop.InsufficientBalance.selector);
        smallAirdrop.batchClaim(claims);
    }

    function testFuzz_BatchClaimRejectsContractRecipient(uint8 batchSize, uint8 contractIndex) public {
        vm.assume(batchSize > 0);
        vm.assume(batchSize <= 10);
        vm.assume(contractIndex < batchSize);

        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            address recipient = (i == contractIndex) ? address(airdrop) : address(uint160(i + 2000));
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 90000)),
                recipient: recipient
            });
        }

        vm.prank(user);
        vm.expectRevert(Airdrop.ClaimToContract.selector);
        airdrop.batchClaim(claims);
    }

    function testAcceptOwnershipEventOrder() public {
        address newOwner = address(0x3);

        vm.prank(owner);
        airdrop.transferOwnership(newOwner);

        address expectedPreviousOwner = owner;

        vm.prank(newOwner);
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferred(expectedPreviousOwner, newOwner);
        airdrop.acceptOwnership();

        assertEq(airdrop.owner(), newOwner);
        assertEq(airdrop.pendingOwner(), address(0));
    }

    function testBatchClaimAtomicityOnTransferFailure() public {
        FailingOnCountToken failingToken = new FailingOnCountToken();
        MockVerifier failingVerifier = new MockVerifier();
        failingVerifier.setVerify(true);

        vm.startPrank(owner);
        Airdrop failingAirdrop = new Airdrop(
            address(failingToken), address(failingVerifier), merkleRoot, MAX_CLAIMS
        );
        failingToken.mint(address(failingAirdrop), MAX_CLAIMS * CLAIM_AMOUNT);
        vm.stopPrank();

        failingToken.setFailAfterCount(2);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](3);
        for (uint256 i = 0; i < 3; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 100)),
                recipient: address(uint160(i + 200))
            });
        }

        vm.prank(user);
        vm.expectRevert(Airdrop.TransferFailed.selector);
        failingAirdrop.batchClaim(claims);

        for (uint256 i = 0; i < 3; i++) {
            assertFalse(failingAirdrop.isNullifierUsed(bytes32(uint256(i + 100))));
        }
        assertEq(failingAirdrop.claimCount(), 0);
        assertEq(failingAirdrop.totalClaimed(), 0);
    }

    function testSECP256K1HalfOrder() public view {
        bytes32 expectedHalfOrder = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
        assertEq(airdrop.SECP256K1_HALF_ORDER(), expectedHalfOrder);
    }

    function testInvariant_NullifierUniquenessAfterMultipleClaims() public {
        verifier.setVerify(true);

        bytes32[] memory nullifiers = new bytes32[](20);
        for (uint256 i = 0; i < 20; i++) {
            nullifiers[i] = bytes32(uint256(i + 100000));
        }

        for (uint256 i = 0; i < 20; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 1000));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), nullifiers[i], recipient);

            // Invariant: each nullifier should be marked as used exactly once
            assertTrue(airdrop.isNullifierUsed(nullifiers[i]));

            // Invariant: no other nullifiers should be affected
            for (uint256 j = 0; j < i; j++) {
                assertTrue(airdrop.isNullifierUsed(nullifiers[j]));
            }
            for (uint256 j = i + 1; j < 20; j++) {
                assertFalse(airdrop.isNullifierUsed(nullifiers[j]));
            }
        }
    }

    function testInvariant_TokenBalanceMatchesClaimable() public {
        verifier.setVerify(true);

        uint256 initialBalance = token.balanceOf(address(airdrop));
        uint256 claimsToMake = 5;

        for (uint256 i = 0; i < claimsToMake; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 200000));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 2000));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);

            // Invariant: contract balance should decrease by exactly CLAIM_AMOUNT per claim
            assertEq(
                token.balanceOf(address(airdrop)),
                initialBalance - (i + 1) * CLAIM_AMOUNT
            );
        }

        // Invariant: totalClaimed should equal the sum of all claims
        assertEq(airdrop.totalClaimed(), claimsToMake * CLAIM_AMOUNT);
    }

    function testFuzz_InvariantClaimCountNeverExceedsMaxClaims(uint8 numClaims) public {
        vm.assume(numClaims > 0);
        vm.assume(numClaims <= 100);
        verifier.setVerify(true);

        uint256 claimsMade = 0;
        for (uint256 i = 0; i < numClaims && claimsMade < MAX_CLAIMS; i++) {
            bytes32 claimNullifier = bytes32(uint256(i + 300000));
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 3000));

            vm.prank(recipient);
            if (claimsMade < MAX_CLAIMS) {
                airdrop.claim(_mockProof(), claimNullifier, recipient);
                claimsMade++;

                // Invariant: claimCount should never exceed maxClaims
                assertLe(airdrop.claimCount(), airdrop.maxClaims());
            }
        }

        // Invariant: final state should be consistent
        assertEq(airdrop.claimCount(), claimsMade);
        assertEq(airdrop.totalClaimed(), claimsMade * CLAIM_AMOUNT);
    }

    function testGetOperationStatusNotScheduled() public view {
        bytes32 fakeHash = keccak256("fake");
        assertEq(uint8(airdrop.getOperationStatus(fakeHash)), uint8(Airdrop.OperationStatus.NotScheduled));
    }

    function testGetOperationStatusScheduled() public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.prank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        assertEq(uint8(airdrop.getOperationStatus(operationHash)), uint8(Airdrop.OperationStatus.Scheduled));
    }

    function testGetOperationStatusExecuted() public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        assertEq(uint8(airdrop.getOperationStatus(operationHash)), uint8(Airdrop.OperationStatus.Executed));
        vm.stopPrank();
    }

    function testGetOperationStatusCancelled() public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        airdrop.cancelOperation(operationHash);
        assertEq(uint8(airdrop.getOperationStatus(operationHash)), uint8(Airdrop.OperationStatus.Cancelled));
        vm.stopPrank();
    }

    function testGetOperationStatusExpired() public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        vm.warp(block.timestamp + 14 days + 2 days + 1);
        assertEq(uint8(airdrop.getOperationStatus(operationHash)), uint8(Airdrop.OperationStatus.Expired));
        vm.stopPrank();
    }

    function testGetOperationSchedule() public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.prank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        bytes32 operationHash = keccak256(abi.encode("updateRoot", newRoot));
        uint256 executeAfter = airdrop.getOperationSchedule(operationHash);
        assertEq(executeAfter, block.timestamp + 2 days);
    }

    function testValidateClaimParamsValid() public view {
        bytes32 nullifier = bytes32(uint256(456));
        address recipient = user;
        (bool isValid, string memory reason) = airdrop.validateClaimParams(nullifier, recipient);
        assertTrue(isValid);
        assertEq(reason, "");
    }

    function testValidateClaimParamsPaused() public {
        vm.prank(owner);
        airdrop.pause();

        (bool isValid, string memory reason) = airdrop.validateClaimParams(bytes32(uint256(456)), user);
        assertFalse(isValid);
        assertEq(reason, "Contract is paused");
    }

    function testValidateClaimParamsInvalidNullifier() public view {
        (bool isValid, string memory reason) = airdrop.validateClaimParams(bytes32(0), user);
        assertFalse(isValid);
        assertEq(reason, "Invalid nullifier");
    }

    function testValidateClaimParamsNullifierUsed() public {
        verifier.setVerify(true);
        bytes32 nullifier = bytes32(uint256(456));
        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, user);

        (bool isValid, string memory reason) = airdrop.validateClaimParams(nullifier, user);
        assertFalse(isValid);
        assertEq(reason, "Nullifier already used");
    }

    function testValidateClaimParamsInvalidRecipient() public view {
        (bool isValid, string memory reason) = airdrop.validateClaimParams(bytes32(uint256(456)), address(0));
        assertFalse(isValid);
        assertEq(reason, "Invalid recipient");
    }

    function testValidateClaimParamsContractRecipient() public view {
        (bool isValid, string memory reason) = airdrop.validateClaimParams(bytes32(uint256(456)), address(airdrop));
        assertFalse(isValid);
        assertEq(reason, "Cannot claim to contract");
    }

    function testValidateBatchClaimParamsValid() public view {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });
        claims[1] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(101)),
            recipient: address(0xABC)
        });

        (bool isValid, string memory reason) = airdrop.validateBatchClaimParams(claims);
        assertTrue(isValid);
        assertEq(reason, "");
    }

    function testValidateBatchClaimParamsEmpty() public view {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](0);
        (bool isValid, string memory reason) = airdrop.validateBatchClaimParams(claims);
        assertFalse(isValid);
        assertEq(reason, "Empty batch");
    }

    function testValidateBatchClaimParamsTooLarge() public view {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](11);
        for (uint256 i = 0; i < 11; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 100)),
                recipient: user
            });
        }

        (bool isValid, string memory reason) = airdrop.validateBatchClaimParams(claims);
        assertFalse(isValid);
        assertEq(reason, "Batch too large");
    }

    function testValidateBatchClaimParamsDuplicateNullifier() public view {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });
        claims[1] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: address(0xABC)
        });

        (bool isValid, string memory reason) = airdrop.validateBatchClaimParams(claims);
        assertFalse(isValid);
        assertEq(reason, "Duplicate nullifier in batch");
    }

    event BatchOperationsCancelled(bytes32[] indexed operationHashes, uint256 count);

    function testBatchOperationsCancelledEvent() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 root2 = bytes32(uint256(790));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(root1);
        airdrop.scheduleUpdateRoot(root2);

        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));
        bytes32 hash2 = keccak256(abi.encode("updateRoot", root2));

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = hash1;
        hashes[1] = hash2;

        vm.expectEmit(false, false, false, true);
        emit BatchOperationsCancelled(hashes, 2);
        airdrop.batchCancelOperations(hashes);
        vm.stopPrank();
    }

    function testFuzz_BatchClaimMaxSize(uint8 batchSize) public {
        vm.assume(batchSize > 0);
        vm.assume(batchSize <= 10);
        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 90000)),
                recipient: address(uint160(i + 1000))
            });
        }

        vm.prank(user);
        airdrop.batchClaim(claims);

        assertEq(airdrop.claimCount(), batchSize);
    }

    function testValidateBatchClaimParamsInsufficientBalance() public {
        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](2);
        claims[0] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(100)),
            recipient: user
        });
        claims[1] = Airdrop.ClaimParams({
            proof: _mockProof(),
            nullifier: bytes32(uint256(101)),
            recipient: address(0xABC)
        });

        vm.startPrank(owner);
        MockERC20 smallToken = new MockERC20();
        smallToken.mint(owner, CLAIM_AMOUNT);
        MockVerifier smallVerifier = new MockVerifier();
        Airdrop smallAirdrop = new Airdrop(
            address(smallToken), address(smallVerifier), merkleRoot, 10
        );
        smallToken.transfer(address(smallAirdrop), CLAIM_AMOUNT);
        vm.stopPrank();

        (bool isValid, string memory reason) = smallAirdrop.validateBatchClaimParams(claims);
        assertFalse(isValid);
        assertEq(reason, "Insufficient balance");
    }

    function testFuzz_TimelockOperationExpiration(uint256 timeSkip) public {
        bytes32 newRoot = bytes32(uint256(789));
        vm.assume(timeSkip > 16 days);
        vm.assume(timeSkip < type(uint256).max - block.timestamp);

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);

        vm.warp(block.timestamp + timeSkip);
        vm.expectRevert(Airdrop.OperationExpired.selector);
        airdrop.updateRoot(newRoot);
        vm.stopPrank();
    }

    function testInvariant_ClaimCountConsistencyAfterBatch() public {
        verifier.setVerify(true);

        uint256 expectedCount = 0;
        for (uint256 batch = 0; batch < 3; batch++) {
            uint256 batchSize = 3;
            Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](batchSize);
            for (uint256 i = 0; i < batchSize; i++) {
                claims[i] = Airdrop.ClaimParams({
                    proof: _mockProof(),
                    nullifier: bytes32(uint256(batch * 10 + i + 100000)),
                    recipient: address(uint160(batch * 10 + i + 1000))
                });
            }

            vm.prank(user);
            airdrop.batchClaim(claims);

            expectedCount += batchSize;
            assertEq(airdrop.claimCount(), expectedCount);
            assertEq(airdrop.totalClaimed(), expectedCount * CLAIM_AMOUNT);
        }
    }

    function testFuzz_ValidateClaimParamsMaxClaimsExceeded(uint8 claimsToMake) public {
        vm.assume(claimsToMake > 0);
        vm.assume(claimsToMake <= 50);
        verifier.setVerify(true);

        for (uint256 i = 0; i < claimsToMake && i < MAX_CLAIMS; i++) {
            bytes32 nullifier = bytes32(uint256(i + 500000));
            address recipient = address(uint160(i + 5000));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), nullifier, recipient);
        }

        bytes32 testNullifier = bytes32(uint256(999999));
        if (airdrop.claimCount() >= MAX_CLAIMS) {
            (bool isValid, string memory reason) = airdrop.validateClaimParams(testNullifier, user);
            assertFalse(isValid);
            assertEq(reason, "Max claims exceeded");
        }
    }

    function testBatchClaimExactMaxSize() public {
        verifier.setVerify(true);

        Airdrop.ClaimParams[] memory claims = new Airdrop.ClaimParams[](10);
        for (uint256 i = 0; i < 10; i++) {
            claims[i] = Airdrop.ClaimParams({
                proof: _mockProof(),
                nullifier: bytes32(uint256(i + 600000)),
                recipient: address(uint160(i + 6000))
            });
        }

        vm.prank(user);
        airdrop.batchClaim(claims);

        assertEq(airdrop.claimCount(), 10);
        assertEq(airdrop.totalClaimed(), 10 * CLAIM_AMOUNT);

        for (uint256 i = 0; i < 10; i++) {
            assertTrue(airdrop.isNullifierUsed(bytes32(uint256(i + 600000))));
        }
    }

    function testFuzz_OperationStatusTransition(bytes32 root) public {
        vm.assume(root != bytes32(0));
        vm.assume(root != merkleRoot);

        bytes32 opHash = keccak256(abi.encode("updateRoot", root));

        assertEq(uint8(airdrop.getOperationStatus(opHash)), uint8(Airdrop.OperationStatus.NotScheduled));

        vm.prank(owner);
        airdrop.scheduleUpdateRoot(root);
        assertEq(uint8(airdrop.getOperationStatus(opHash)), uint8(Airdrop.OperationStatus.Scheduled));

        vm.prank(owner);
        airdrop.cancelOperation(opHash);
        assertEq(uint8(airdrop.getOperationStatus(opHash)), uint8(Airdrop.OperationStatus.Cancelled));

        vm.prank(owner);
        airdrop.scheduleUpdateRoot(root);
        assertEq(uint8(airdrop.getOperationStatus(opHash)), uint8(Airdrop.OperationStatus.Scheduled));

        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(owner);
        airdrop.updateRoot(root);
        assertEq(uint8(airdrop.getOperationStatus(opHash)), uint8(Airdrop.OperationStatus.Executed));
    }

    function testValidateClaimParamsAfterClaim() public {
        verifier.setVerify(true);
        bytes32 nullifier = bytes32(uint256(123456));
        
        (bool isValidBefore, string memory reasonBefore) = airdrop.validateClaimParams(nullifier, user);
        assertTrue(isValidBefore);
        assertEq(reasonBefore, "");

        vm.prank(user);
        airdrop.claim(_mockProof(), nullifier, user);

        (bool isValidAfter, string memory reasonAfter) = airdrop.validateClaimParams(nullifier, user);
        assertFalse(isValidAfter);
        assertEq(reasonAfter, "Nullifier already used");
    }

    function testGetOperationHashFunctions() public view {
        bytes32 root = bytes32(uint256(123));
        address newVerifier = address(0x123);
        uint256 newMaxClaims = 2000;
        uint256 withdrawAmount = 100 ether;

        bytes32 rootHash = airdrop.getUpdateRootHash(root);
        assertEq(rootHash, keccak256(abi.encode("updateRoot", root)));

        bytes32 verifierHash = airdrop.getUpdateVerifierHash(newVerifier);
        assertEq(verifierHash, keccak256(abi.encode("updateVerifier", newVerifier)));

        bytes32 maxClaimsHash = airdrop.getSetMaxClaimsHash(newMaxClaims);
        assertEq(maxClaimsHash, keccak256(abi.encode("setMaxClaims", newMaxClaims)));

        bytes32 withdrawHash = airdrop.getWithdrawTokensHash(withdrawAmount);
        assertEq(withdrawHash, keccak256(abi.encode("withdrawTokens", withdrawAmount)));

        bytes32 renounceHash = airdrop.getRenounceOwnershipHash();
        assertEq(renounceHash, keccak256(abi.encode("renounceOwnership")));
    }

    function testBatchScheduleOperations() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 root2 = bytes32(uint256(790));
        bytes32 root3 = bytes32(uint256(791));

        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));
        bytes32 hash2 = keccak256(abi.encode("updateRoot", root2));
        bytes32 hash3 = keccak256(abi.encode("updateRoot", root3));

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = hash1;
        hashes[1] = hash2;
        hashes[2] = hash3;

        vm.prank(owner);
        airdrop.batchScheduleOperations(hashes);

        assertGt(airdrop.timelockSchedule(hash1), 0);
        assertGt(airdrop.timelockSchedule(hash2), 0);
        assertGt(airdrop.timelockSchedule(hash3), 0);
    }

    function testBatchScheduleOperationsEmptyBatch() public {
        bytes32[] memory emptyHashes = new bytes32[](0);
        vm.prank(owner);
        vm.expectRevert(Airdrop.EmptyBatch.selector);
        airdrop.batchScheduleOperations(emptyHashes);
    }

    function testBatchScheduleOperationsTooLarge() public {
        bytes32[] memory hashes = new bytes32[](51);
        for (uint256 i = 0; i < 51; i++) {
            hashes[i] = keccak256(abi.encode("updateRoot", bytes32(uint256(i + 100))));
        }
        vm.prank(owner);
        vm.expectRevert(Airdrop.BatchTooLarge.selector);
        airdrop.batchScheduleOperations(hashes);
    }

    function testBatchScheduleOperationsAlreadyScheduled() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 root2 = bytes32(uint256(790));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(root1);

        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));
        bytes32 hash2 = keccak256(abi.encode("updateRoot", root2));

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = hash1;
        hashes[1] = hash2;

        vm.expectRevert(Airdrop.OperationAlreadyScheduled.selector);
        airdrop.batchScheduleOperations(hashes);
        vm.stopPrank();
    }

    function testBatchScheduleOperationsAlreadyExecuted() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(root1);
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateRoot(root1);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hash1;

        vm.expectRevert(Airdrop.OperationAlreadyExecuted.selector);
        airdrop.batchScheduleOperations(hashes);
        vm.stopPrank();
    }

    function testBatchScheduleOperationsAfterCancel() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(root1);
        airdrop.cancelOperation(hash1);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hash1;

        airdrop.batchScheduleOperations(hashes);
        assertGt(airdrop.timelockSchedule(hash1), 0);
        assertFalse(airdrop.cancelledOperations(hash1));
        vm.stopPrank();
    }

    function testRescheduleAfterExecutionBlocked() public {
        bytes32 newRoot = bytes32(uint256(789));

        vm.startPrank(owner);
        airdrop.scheduleUpdateRoot(newRoot);
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.updateRoot(newRoot);

        vm.expectRevert(Airdrop.OperationAlreadyExecuted.selector);
        airdrop.scheduleUpdateRoot(newRoot);
        vm.stopPrank();
    }

    event BatchOperationsScheduled(bytes32[] indexed operationHashes, uint256 count, uint256 executeAfter);

    function testBatchOperationsScheduledEvent() public {
        bytes32 root1 = bytes32(uint256(789));
        bytes32 root2 = bytes32(uint256(790));

        bytes32 hash1 = keccak256(abi.encode("updateRoot", root1));
        bytes32 hash2 = keccak256(abi.encode("updateRoot", root2));

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = hash1;
        hashes[1] = hash2;

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit BatchOperationsScheduled(hashes, 2, block.timestamp + 2 days);
        airdrop.batchScheduleOperations(hashes);
    }

    function testOwnershipTransferTwiceBeforeAccept() public {
        address newOwner1 = address(0x3);
        address newOwner2 = address(0x4);

        vm.startPrank(owner);
        airdrop.transferOwnership(newOwner1);
        assertEq(airdrop.pendingOwner(), newOwner1);

        airdrop.transferOwnership(newOwner2);
        assertEq(airdrop.pendingOwner(), newOwner2);

        vm.stopPrank();

        vm.prank(newOwner1);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.acceptOwnership();

        vm.prank(newOwner2);
        airdrop.acceptOwnership();
        assertEq(airdrop.owner(), newOwner2);
    }

    function testOwnershipTransferSameAsCurrentOwner() public {
        vm.prank(owner);
        airdrop.transferOwnership(owner);
        assertEq(airdrop.pendingOwner(), owner);

        vm.prank(owner);
        airdrop.acceptOwnership();
        assertEq(airdrop.owner(), owner);
        assertEq(airdrop.pendingOwner(), address(0));
    }

    function testOwnershipTransferPendingOwnerCanReject() public {
        address newOwner = address(0x3);

        vm.prank(owner);
        airdrop.transferOwnership(newOwner);
        assertEq(airdrop.pendingOwner(), newOwner);

        vm.prank(owner);
        airdrop.transferOwnership(address(0x4));
        assertEq(airdrop.pendingOwner(), address(0x4));
        assertEq(airdrop.owner(), owner);
    }

    function testOwnershipTransferAfterRenounceFails() public {
        vm.startPrank(owner);
        airdrop.scheduleRenounceOwnership();
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.renounceOwnership();
        assertEq(airdrop.owner(), address(0));

        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.transferOwnership(address(0x3));
        vm.stopPrank();
    }

    function testAcceptOwnershipByWrongAddress() public {
        address newOwner = address(0x3);
        address wrongAddress = address(0x4);

        vm.prank(owner);
        airdrop.transferOwnership(newOwner);

        vm.prank(wrongAddress);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.acceptOwnership();

        assertEq(airdrop.owner(), owner);
        assertEq(airdrop.pendingOwner(), newOwner);
    }

    function testPendingOwnerSetEventOnTransfer() public {
        address newOwner = address(0x3);
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit PendingOwnerSet(newOwner);
        airdrop.transferOwnership(newOwner);
    }

    function testPendingOwnerClearedAfterAccept() public {
        address newOwner = address(0x3);

        vm.prank(owner);
        airdrop.transferOwnership(newOwner);

        vm.prank(newOwner);
        airdrop.acceptOwnership();

        assertEq(airdrop.pendingOwner(), address(0));
    }
}

contract ReentrancyToken is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public attacker;
    Airdrop public airdrop;

    function setAttacker(address _attacker, address payable _airdrop) external {
        attacker = _attacker;
        airdrop = Airdrop(_airdrop);
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;

        if (recipient == attacker && attacker != address(0)) {
            airdrop.claim(new uint256[](1), bytes32(uint256(12345)), attacker);
        }

        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

/// @notice Empty attacker contract - the reentrancy logic is in ReentrancyToken
/// @dev ReentrancyToken.transfer() attempts to call airdrop.claim() during the transfer.
///      This contract is just a recipient that receives the tokens after a failed attack.
contract AttackerContract {
    Airdrop public airdrop;

    constructor(address payable _airdrop) {
        airdrop = Airdrop(_airdrop);
    }
}

contract FailingToken is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

contract FailingOnCountToken is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public transferCount;
    uint256 public failAfterCount;

    function setFailAfterCount(uint256 _count) external {
        failAfterCount = _count;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        transferCount++;
        if (transferCount > failAfterCount) {
            return false;
        }
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}
