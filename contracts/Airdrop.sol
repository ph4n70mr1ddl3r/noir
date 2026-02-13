// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUltraVerifier {
    function verify(uint256[] calldata _proof, uint256[] calldata _publicInputs) external view returns (bool);
}

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ReentrancyGuard {
    // Using uint256 values 1 and 2 instead of bool true/false for lock state
    // This unconventional pattern still works correctly as 1 = unlocked, 2 = locked
    uint256 private locked = 1;
    error ReentrancyGuardReentrantCall();

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() internal {
        if (locked != 1) revert ReentrancyGuardReentrantCall();
        locked = 2;
    }

    function _nonReentrantAfter() internal {
        locked = 1;
    }
}

contract Airdrop is ReentrancyGuard {
    error NullifierAlreadyUsed();
    error InvalidProof();
    error InvalidRoot();
    error InsufficientBalance();
    error NotOwner();
    error TransferFailed();
    error InvalidRecipient();
    error InvalidVerifier();
    error TimelockNotExpired();
    error MaxClaimsExceeded();
    error InvalidTimelock();
    error OperationNotScheduled();
    error OperationAlreadyExecuted();
    error InvalidMaxClaims();
    error OperationAlreadyCancelled();
    error OperationAlreadyScheduled();
    error EmptyProof();
    error MaxClaimsBelowCurrent();

    address public owner;
    address public pendingOwner;
    IERC20 public token;
    IUltraVerifier public verifier;
    bytes32 public merkleRoot;

    // Amount of tokens each claimer receives (100 tokens, 18 decimals)
    uint256 public constant CLAIM_AMOUNT = 100 * 10 ** 18;
    uint256 public totalClaimed;
    // Maximum number of claims allowed to prevent contract draining
    uint256 public maxClaims;

    // Timelock delay for sensitive owner operations (2 days = 48 hours)
    uint256 public constant TIMELOCK_DELAY = 2 days;
    mapping(bytes32 => uint256) public timelockSchedule;
    mapping(bytes32 => bool) public executedOperations;

    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(address indexed recipient, bytes32 indexed nullifier);
    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event RootInitialized(bytes32 indexed root);
    event MaxClaimsSet(uint256 maxClaims);
    event TimelockScheduled(bytes32 indexed operationHash, uint256 executeAfter);
    event OperationExecuted(bytes32 indexed operationHash);
    event OperationCancelled(bytes32 indexed operationHash);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PendingOwnerSet(address indexed pendingOwner);

    constructor(address _token, address _verifier, bytes32 _merkleRoot, uint256 _maxClaims) {
        if (_token == address(0)) revert InvalidRecipient();
        if (_verifier == address(0)) revert InvalidVerifier();
        if (_merkleRoot == bytes32(0)) revert InvalidRoot();
        if (_maxClaims == 0) revert InvalidMaxClaims();
        owner = msg.sender;
        token = IERC20(_token);
        verifier = IUltraVerifier(_verifier);
        merkleRoot = _merkleRoot;
        maxClaims = _maxClaims;
        emit RootInitialized(_merkleRoot);
        emit MaxClaimsSet(_maxClaims);
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _hashOperation(bytes memory data) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := add(data, 32)
            result := keccak256(ptr, mload(data))
        }
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidRecipient();
        pendingOwner = newOwner;
        emit PendingOwnerSet(newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        delete pendingOwner;
    }

    function cancelOperation(bytes32 operationHash) external onlyOwner {
        if (executedOperations[operationHash]) revert OperationAlreadyExecuted();
        if (timelockSchedule[operationHash] == 0) revert OperationNotScheduled();
        delete timelockSchedule[operationHash];
        emit OperationCancelled(operationHash);
    }

    function claim(uint256[] calldata proof, bytes32 nullifier, address recipient) external nonReentrant {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (recipient == address(0)) revert InvalidRecipient();
        if (proof.length == 0) revert EmptyProof();

        if (totalClaimed / CLAIM_AMOUNT >= maxClaims) revert MaxClaimsExceeded();

        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(merkleRoot);
        publicInputs[1] = uint256(uint160(recipient));
        publicInputs[2] = uint256(nullifier);

        bool isValid = verifier.verify(proof, publicInputs);
        if (!isValid) revert InvalidProof();

        usedNullifiers[nullifier] = true;
        uint256 newTotal = totalClaimed + CLAIM_AMOUNT;
        if (newTotal < totalClaimed) revert MaxClaimsExceeded();
        totalClaimed = newTotal;

        (bool success, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, recipient, CLAIM_AMOUNT));
        if (!success) revert TransferFailed();
        if (data.length > 0 && !abi.decode(data, (bool))) revert TransferFailed();

        emit Claimed(recipient, nullifier);
    }

    function updateRoot(bytes32 newRoot) external onlyOwner {
        if (newRoot == bytes32(0)) revert InvalidRoot();
        bytes32 operationHash = _hashOperation(abi.encode("updateRoot", newRoot));
        _executeTimelockedOperation(operationHash);
        bytes32 oldRoot = merkleRoot;
        merkleRoot = newRoot;
        emit RootUpdated(oldRoot, newRoot);
    }

    function updateVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidVerifier();
        bytes32 operationHash = _hashOperation(abi.encode("updateVerifier", newVerifier));
        _executeTimelockedOperation(operationHash);
        address oldVerifier = address(verifier);
        verifier = IUltraVerifier(newVerifier);
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    function setMaxClaims(uint256 _maxClaims) external onlyOwner {
        if (_maxClaims == 0) revert InvalidMaxClaims();
        if (_maxClaims < totalClaimed / CLAIM_AMOUNT) revert MaxClaimsBelowCurrent();
        bytes32 operationHash = _hashOperation(abi.encode("setMaxClaims", _maxClaims));
        _executeTimelockedOperation(operationHash);
        maxClaims = _maxClaims;
        emit MaxClaimsSet(_maxClaims);
    }

    function withdrawTokens(uint256 amount) external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("withdrawTokens", amount));
        _executeTimelockedOperation(operationHash);
        _withdrawTokensInternal(amount);
    }

    function scheduleWithdrawTokens(uint256 amount) external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("withdrawTokens", amount));
        if (timelockSchedule[operationHash] != 0) revert OperationAlreadyScheduled();
        timelockSchedule[operationHash] = block.timestamp + TIMELOCK_DELAY;
        emit TimelockScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    function _withdrawTokensInternal(uint256 amount) internal {
        (bool success, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, owner, amount));
        if (!success) revert TransferFailed();
        if (data.length > 0 && !abi.decode(data, (bool))) revert TransferFailed();
    }

    // Schedule a timelocked operation (must be called before execute)
    function scheduleUpdateRoot(bytes32 newRoot) external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("updateRoot", newRoot));
        if (timelockSchedule[operationHash] != 0) revert OperationAlreadyScheduled();
        timelockSchedule[operationHash] = block.timestamp + TIMELOCK_DELAY;
        emit TimelockScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    function scheduleUpdateVerifier(address newVerifier) external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("updateVerifier", newVerifier));
        if (timelockSchedule[operationHash] != 0) revert OperationAlreadyScheduled();
        timelockSchedule[operationHash] = block.timestamp + TIMELOCK_DELAY;
        emit TimelockScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    function scheduleSetMaxClaims(uint256 _maxClaims) external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("setMaxClaims", _maxClaims));
        if (timelockSchedule[operationHash] != 0) revert OperationAlreadyScheduled();
        timelockSchedule[operationHash] = block.timestamp + TIMELOCK_DELAY;
        emit TimelockScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    // Helper function to execute timelocked operations
    function _executeTimelockedOperation(bytes32 operationHash) internal {
        uint256 executeAfter = timelockSchedule[operationHash];
        if (executeAfter == 0 || block.timestamp < executeAfter) revert TimelockNotExpired();
        if (executedOperations[operationHash]) revert InvalidTimelock();

        executedOperations[operationHash] = true;
        delete timelockSchedule[operationHash];
        emit OperationExecuted(operationHash);
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }
}
