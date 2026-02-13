// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Airdrop, IUltraVerifier, IERC20} from "./Airdrop.sol";

contract MockVerifier is IUltraVerifier {
    bool shouldVerify = true;

    function setVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    function verify(uint256[] calldata, uint256[] calldata) external view returns (bool) {
        return shouldVerify;
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

        verifier.setVerify(true);
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

    function testClaimMaxClaimsExceeded() public {
        verifier.setVerify(true);

        for (uint256 i = 0; i < MAX_CLAIMS; i++) {
            bytes32 claimNullifier = bytes32(i);
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 100));
            vm.prank(recipient);
            airdrop.claim(_mockProof(), claimNullifier, recipient);
        }

        bytes32 finalNullifier = bytes32(MAX_CLAIMS + 1);
        verifier.setVerify(true);
        vm.prank(user);
        vm.expectRevert(Airdrop.MaxClaimsExceeded.selector);
        airdrop.claim(_mockProof(), finalNullifier, user);
    }

    function testClaimMaxClaimsBoundary() public {
        verifier.setVerify(true);

        for (uint256 i = 0; i < MAX_CLAIMS - 1; i++) {
            bytes32 claimNullifier = bytes32(i);
            // forge-lint: disable-next-line(unsafe-typecast)
            address claimRecipient = address(uint160(i + 100));
            vm.prank(claimRecipient);
            airdrop.claim(_mockProof(), claimNullifier, claimRecipient);
        }

        bytes32 nullifier = bytes32(MAX_CLAIMS - 1);
        // forge-lint: disable-next-line(unsafe-typecast)
        address boundaryRecipient = address(uint160(MAX_CLAIMS - 1 + 100));
        vm.prank(boundaryRecipient);
        airdrop.claim(_mockProof(), nullifier, boundaryRecipient);

        bytes32 finalNullifier = bytes32(MAX_CLAIMS + 100);
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

    function testSetMaxClaimsTimelock() public {
        uint256 newMaxClaims = 2000;

        vm.startPrank(owner);
        airdrop.scheduleSetMaxClaims(newMaxClaims);

        // Execute after timelock
        vm.warp(block.timestamp + 2 days + 1);
        airdrop.setMaxClaims(newMaxClaims);
        assertEq(airdrop.maxClaims(), newMaxClaims);
        vm.stopPrank();
    }

    function testOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.scheduleUpdateRoot(bytes32(0));

        vm.prank(user);
        vm.expectRevert(Airdrop.NotOwner.selector);
        airdrop.updateRoot(bytes32(0));
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

    function testReentrancyGuard() public {
        ReentrancyToken reentrancyToken = new ReentrancyToken();
        MockVerifier reentrancyVerifier = new MockVerifier();
        reentrancyVerifier.setVerify(true);

        vm.startPrank(owner);
        Airdrop reentrancyAirdrop =
            new Airdrop(address(reentrancyToken), address(reentrancyVerifier), merkleRoot, MAX_CLAIMS);
        reentrancyToken.mint(address(reentrancyAirdrop), MAX_CLAIMS * CLAIM_AMOUNT);
        vm.stopPrank();

        Malicious attacker = new Malicious(address(reentrancyAirdrop));
        reentrancyToken.setAttacker(address(attacker), address(reentrancyAirdrop));

        bytes32 nullifier = bytes32(uint256(999));

        vm.prank(address(attacker));
        vm.expectRevert(Airdrop.TransferFailed.selector);
        reentrancyAirdrop.claim(_mockProof(), nullifier, address(attacker));

        assertFalse(reentrancyAirdrop.isNullifierUsed(nullifier));
    }

    function testZeroAddressInConstructor() public {
        vm.startPrank(owner);
        vm.expectRevert(Airdrop.InvalidRecipient.selector);
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

    function testPendingOwnerSetEvent() public {
        address newOwner = address(0x3);
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit PendingOwnerSet(newOwner);
        airdrop.transferOwnership(newOwner);
        assertEq(airdrop.pendingOwner(), newOwner);
    }

    event PendingOwnerSet(address indexed pendingOwner);

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
            bytes32 claimNullifier = bytes32(i);
            // forge-lint: disable-next-line(unsafe-typecast)
            address recipient = address(uint160(i + 100));
            vm.prank(recipient);
            airdrop.claim(new uint256[](1), claimNullifier, recipient);
        }

        vm.startPrank(owner);
        airdrop.scheduleSetMaxClaims(3);
        vm.warp(block.timestamp + 2 days + 1);
        vm.expectRevert(Airdrop.MaxClaimsBelowCurrent.selector);
        airdrop.setMaxClaims(3);
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
}

contract ReentrancyToken is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public attacker;
    Airdrop public airdrop;

    function setAttacker(address _attacker, address _airdrop) external {
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

contract Malicious {
    Airdrop public airdrop;

    constructor(address _airdrop) {
        airdrop = Airdrop(_airdrop);
    }
}
