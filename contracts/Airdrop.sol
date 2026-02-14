// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUltraVerifier {
    function verify(uint256[] calldata _proof, uint256[] calldata _publicInputs)
        external
        view
        returns (bool);
}

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ReentrancyGuard {
    bool private locked = false;

    error ReentrancyGuardReentrantCall();

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() internal {
        if (locked) revert ReentrancyGuardReentrantCall();
        locked = true;
    }

    function _nonReentrantAfter() internal {
        locked = false;
    }
}

/// @title Noir ZK Airdrop Contract
/// @notice Enables private token claims using zero-knowledge proofs
/// @dev Users prove membership in a Merkle tree without revealing their private key on-chain
///
/// Domain Separator: 0xa1b2c3d4 (bytes 28-31 of 32-byte array)
/// Used in nullifier computation to prevent cross-context replay attacks.
/// Must match the value in Noir circuit (main.nr) and CLI (common.rs).
contract Airdrop is ReentrancyGuard {
    /// @notice Domain separator for nullifier computation (bytes 28-31 of 32-byte array)
    /// @dev Used to prevent cross-context replay attacks. Must match CLI and circuit.
    bytes4 public constant DOMAIN_SEPARATOR = 0xa1b2c3d4;

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
    error OperationAlreadyScheduled();
    error OperationAlreadyCancelled();
    error EmptyProof();
    error MaxClaimsBelowCurrent();
    error OperationExpired();
    error InvalidToken();
    error ContractPaused();
    error ContractNotPaused();
    error EthNotAccepted();
    error UnknownFunction();
    error InsufficientBalanceForWithdraw();
    error ClaimToContract();
    error InvalidNullifier();

    address public owner;
    address public pendingOwner;
    IERC20 public token;
    IUltraVerifier public verifier;
    bytes32 public merkleRoot;
    bool public paused;

    uint256 public constant CLAIM_AMOUNT = 100 * 10 ** 18;
    uint256 public totalClaimed;
    uint256 public claimCount;
    // Maximum number of claims allowed to prevent contract draining
    uint256 public maxClaims;

    // Timelock delay for sensitive owner operations (2 days = 48 hours)
    uint256 public constant TIMELOCK_DELAY = 2 days;
    // Operations expire after 14 days to prevent indefinite execution
    uint256 public constant TIMELOCK_EXPIRATION = 14 days;
    mapping(bytes32 => uint256) public timelockSchedule;
    mapping(bytes32 => bool) public executedOperations;
    mapping(bytes32 => bool) public cancelledOperations;

    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(address indexed recipient, bytes32 indexed nullifier, uint256 indexed claimCount);
    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event RootInitialized(bytes32 indexed root);
    event MaxClaimsSet(uint256 indexed oldMaxClaims, uint256 indexed newMaxClaims);
    event TimelockScheduled(bytes32 indexed operationHash, uint256 executeAfter);
    event OperationExecuted(bytes32 indexed operationHash);
    event OperationCancelled(bytes32 indexed operationHash);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PendingOwnerSet(address indexed pendingOwner);
    event Paused(address indexed account);
    event Unpaused(address indexed account);
    event TokensWithdrawn(address indexed owner, uint256 amount);

    modifier whenNotPaused() {
        _checkNotPaused();
        _;
    }

    modifier whenPaused() {
        _checkPaused();
        _;
    }

    function _checkNotPaused() internal view {
        if (paused) revert ContractPaused();
    }

    function _checkPaused() internal view {
        if (!paused) revert ContractNotPaused();
    }

    /// @notice Initializes the airdrop contract
    /// @dev Sets up the token, verifier, merkle root, and max claims. Emits RootInitialized and MaxClaimsSet events.
    /// @param _token The ERC20 token to distribute (must not be zero address)
    /// @param _verifier The Noir UltraVerifier contract address (must not be zero address)
    /// @param _merkleRoot The root of the Merkle tree containing qualified addresses (must not be zero)
    /// @param _maxClaims Maximum number of claims allowed (must be greater than zero)
    constructor(address _token, address _verifier, bytes32 _merkleRoot, uint256 _maxClaims) {
        if (_token == address(0)) revert InvalidToken();
        if (_verifier == address(0)) revert InvalidVerifier();
        if (_merkleRoot == bytes32(0)) revert InvalidRoot();
        if (_maxClaims == 0) revert InvalidMaxClaims();
        owner = msg.sender;
        token = IERC20(_token);
        verifier = IUltraVerifier(_verifier);
        merkleRoot = _merkleRoot;
        maxClaims = _maxClaims;
        emit RootInitialized(_merkleRoot);
        emit MaxClaimsSet(0, _maxClaims);
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

    /// @notice Initiates two-step ownership transfer
    /// @dev Sets pendingOwner without transferring ownership immediately.
    ///      The new owner must call acceptOwnership to complete the transfer.
    /// @param newOwner Address of the proposed new owner (must not be zero address)
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidRecipient();
        pendingOwner = newOwner;
        emit PendingOwnerSet(newOwner);
    }

    /// @notice Accepts pending ownership transfer
    /// @dev Only callable by the pending owner. Reverts if no ownership transfer is pending.
    function acceptOwnership() external {
        if (pendingOwner == address(0)) revert InvalidRecipient();
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        delete pendingOwner;
    }

    /// @notice Renounces ownership permanently
    /// @dev Sets owner to address(0). This is irreversible.
    /// Only callable via timelock for safety.
    function renounceOwnership() external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("renounceOwnership"));
        _executeTimelockedOperation(operationHash);
        emit OwnershipTransferred(owner, address(0));
        owner = address(0);
        delete pendingOwner;
    }

    /// @notice Schedules ownership renunciation
    /// @dev Must be called before renounceOwnership. Subject to 2-day timelock.
    function scheduleRenounceOwnership() external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("renounceOwnership"));
        _scheduleOperation(operationHash);
    }

    /// @notice Schedules a Merkle root update
    /// @param newRoot The new Merkle root to set
    /// @dev Must be called before updateRoot. Subject to 2-day timelock.
    function scheduleUpdateRoot(bytes32 newRoot) external onlyOwner {
        if (newRoot == bytes32(0)) revert InvalidRoot();
        bytes32 operationHash = _hashOperation(abi.encode("updateRoot", newRoot));
        _scheduleOperation(operationHash);
    }

    /// @notice Schedules a verifier contract update
    /// @param newVerifier Address of the new verifier contract
    /// @dev Must be called before updateVerifier. Subject to 2-day timelock.
    function scheduleUpdateVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidVerifier();
        bytes32 operationHash = _hashOperation(abi.encode("updateVerifier", newVerifier));
        _scheduleOperation(operationHash);
    }

    /// @notice Schedules a max claims update
    /// @param _maxClaims New maximum claims value
    /// @dev Must be called before setMaxClaims. Subject to 2-day timelock.
    function scheduleSetMaxClaims(uint256 _maxClaims) external onlyOwner {
        if (_maxClaims == 0) revert InvalidMaxClaims();
        if (_maxClaims < claimCount) revert MaxClaimsBelowCurrent();
        bytes32 operationHash = _hashOperation(abi.encode("setMaxClaims", _maxClaims));
        _scheduleOperation(operationHash);
    }

    /// @notice Pauses all claim operations
    /// @dev Only callable by owner. Reverts if already paused.
    function pause() external onlyOwner whenNotPaused {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resumes claim operations
    /// @dev Only callable by owner. Reverts if not currently paused.
    function unpause() external onlyOwner whenPaused {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Claims tokens by providing a valid ZK proof
    /// @dev This function implements the checks-effects-interactions pattern to prevent reentrancy.
    ///      The nullifier is derived from the claimer's private key in the ZK circuit, ensuring
    ///      that each qualified address can only claim once while preserving privacy.
    /// @param proof The zero-knowledge proof generated by the Noir circuit, proving membership
    ///        in the Merkle tree and correct nullifier derivation
    /// @param nullifier Unique identifier to prevent double claims. Derived from H(private_key || domain_separator)
    /// @param recipient Address to receive the tokens. Can differ from the claimer's address,
    ///        allowing claims to be sent to a different wallet for added privacy
    /// @custom:security The function uses nonReentrant modifier and checks all invariants before
    ///        making the external token transfer call
    function claim(uint256[] calldata proof, bytes32 nullifier, address recipient)
        external
        nonReentrant
        whenNotPaused
    {
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (recipient == address(0)) revert InvalidRecipient();
        if (recipient == address(this)) revert ClaimToContract();
        if (proof.length == 0) revert EmptyProof();

        if (claimCount >= maxClaims) revert MaxClaimsExceeded();
        if (token.balanceOf(address(this)) < CLAIM_AMOUNT) revert InsufficientBalance();

        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(merkleRoot);
        publicInputs[1] = uint256(uint160(recipient));
        publicInputs[2] = uint256(nullifier);

        bool isValid = verifier.verify(proof, publicInputs);
        if (!isValid) revert InvalidProof();

        usedNullifiers[nullifier] = true;
        totalClaimed += CLAIM_AMOUNT;
        unchecked {
            ++claimCount;
        }

        (bool success, bytes memory data) = address(token)
            .call(abi.encodeWithSelector(IERC20.transfer.selector, recipient, CLAIM_AMOUNT));
        if (!success) revert TransferFailed();
        if (data.length > 0 && !abi.decode(data, (bool))) revert TransferFailed();

        emit Claimed(recipient, nullifier, claimCount);
    }

    /// @notice Updates the Merkle root after timelock expires
    /// @param newRoot The new Merkle root
    function updateRoot(bytes32 newRoot) external onlyOwner {
        if (newRoot == bytes32(0)) revert InvalidRoot();
        bytes32 operationHash = _hashOperation(abi.encode("updateRoot", newRoot));
        _executeTimelockedOperation(operationHash);
        bytes32 oldRoot = merkleRoot;
        merkleRoot = newRoot;
        emit RootUpdated(oldRoot, newRoot);
    }

    /// @notice Updates the verifier contract after timelock expires
    /// @param newVerifier Address of the new verifier contract
    function updateVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidVerifier();
        bytes32 operationHash = _hashOperation(abi.encode("updateVerifier", newVerifier));
        _executeTimelockedOperation(operationHash);
        address oldVerifier = address(verifier);
        verifier = IUltraVerifier(newVerifier);
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    /// @notice Sets maximum claims after timelock expires
    /// @param _maxClaims New maximum claims value
    function setMaxClaims(uint256 _maxClaims) external onlyOwner {
        if (_maxClaims == 0) revert InvalidMaxClaims();
        if (_maxClaims < claimCount) revert MaxClaimsBelowCurrent();
        bytes32 operationHash = _hashOperation(abi.encode("setMaxClaims", _maxClaims));
        _executeTimelockedOperation(operationHash);
        uint256 oldMaxClaims = maxClaims;
        maxClaims = _maxClaims;
        emit MaxClaimsSet(oldMaxClaims, _maxClaims);
    }

    /// @notice Withdraws tokens to owner after timelock expires
    /// @dev Subject to 2-day timelock. Must call scheduleWithdrawTokens first.
    /// @param amount Amount of tokens to withdraw
    function withdrawTokens(uint256 amount) external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("withdrawTokens", amount));
        _executeTimelockedOperation(operationHash);
        _withdrawTokensInternal(amount);
    }

    /// @notice Schedules a token withdrawal operation
    /// @dev Subject to 2-day timelock before withdrawal can be executed.
    /// @param amount Amount of tokens to withdraw (must not exceed contract balance)
    function scheduleWithdrawTokens(uint256 amount) external onlyOwner {
        if (amount > token.balanceOf(address(this))) revert InsufficientBalanceForWithdraw();
        bytes32 operationHash = _hashOperation(abi.encode("withdrawTokens", amount));
        _scheduleOperation(operationHash);
    }

    function _withdrawTokensInternal(uint256 amount) internal {
        if (amount > token.balanceOf(address(this))) revert InsufficientBalanceForWithdraw();
        (bool success, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, owner, amount));
        if (!success) revert TransferFailed();
        if (data.length > 0 && !abi.decode(data, (bool))) revert TransferFailed();
        emit TokensWithdrawn(owner, amount);
    }

    /// @notice Schedules a timelocked operation
    /// @param operationHash The hash of the operation to schedule
    /// @dev Clears any previous cancellation to allow re-scheduling
    function _scheduleOperation(bytes32 operationHash) internal {
        if (timelockSchedule[operationHash] != 0) revert OperationAlreadyScheduled();
        delete cancelledOperations[operationHash];
        timelockSchedule[operationHash] = block.timestamp + TIMELOCK_DELAY;
        emit TimelockScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Cancels a scheduled timelocked operation
    /// @param operationHash The hash of the operation to cancel
    /// @dev Only callable by owner. Cannot cancel already executed or cancelled operations.
    function cancelOperation(bytes32 operationHash) external onlyOwner {
        if (executedOperations[operationHash]) revert OperationAlreadyExecuted();
        if (cancelledOperations[operationHash]) revert OperationAlreadyCancelled();
        if (timelockSchedule[operationHash] == 0) revert OperationNotScheduled();
        cancelledOperations[operationHash] = true;
        delete timelockSchedule[operationHash];
        emit OperationCancelled(operationHash);
    }

    /// @notice Executes a timelocked operation after delay has passed
    /// @param operationHash The hash of the operation to execute
    /// @dev Reverts if timelock has not expired, has already been executed, or has expired
    function _executeTimelockedOperation(bytes32 operationHash) internal {
        uint256 executeAfter = timelockSchedule[operationHash];
        if (executeAfter == 0 || block.timestamp < executeAfter) revert TimelockNotExpired();
        if (block.timestamp > executeAfter + TIMELOCK_EXPIRATION) revert OperationExpired();
        if (executedOperations[operationHash]) revert OperationAlreadyExecuted();

        executedOperations[operationHash] = true;
        delete timelockSchedule[operationHash];
        emit OperationExecuted(operationHash);
    }

    /// @notice Checks if a nullifier has already been used
    /// @param nullifier The nullifier to check
    /// @return used True if the nullifier has been used, false otherwise
    function isNullifierUsed(bytes32 nullifier) external view returns (bool used) {
        return usedNullifiers[nullifier];
    }

    /// @notice Returns the current token balance of the contract
    /// @return balance The balance of tokens held by the contract
    function claimableBalance() external view returns (uint256 balance) {
        return token.balanceOf(address(this));
    }

    /// @notice Returns the number of remaining claims allowed
    /// @return remaining The number of claims that can still be made
    function remainingClaims() external view returns (uint256 remaining) {
        if (maxClaims <= claimCount) {
            return 0;
        }
        return maxClaims - claimCount;
    }

    /// @notice Returns comprehensive claim-related information
    /// @return _token The ERC20 token address
    /// @return _merkleRoot The current Merkle root
    /// @return _claimAmount The amount of tokens per claim
    /// @return _totalClaimed Total tokens claimed so far
    /// @return _claimCount Number of claims made
    /// @return _maxClaims Maximum allowed claims
    /// @return _remainingClaims Remaining claims allowed
    /// @return _isPaused Whether the contract is paused
    function claimInfo() external view returns (
        address _token,
        bytes32 _merkleRoot,
        uint256 _claimAmount,
        uint256 _totalClaimed,
        uint256 _claimCount,
        uint256 _maxClaims,
        uint256 _remainingClaims,
        bool _isPaused
    ) {
        _token = address(token);
        _merkleRoot = merkleRoot;
        _claimAmount = CLAIM_AMOUNT;
        _totalClaimed = totalClaimed;
        _claimCount = claimCount;
        _maxClaims = maxClaims;
        _remainingClaims = maxClaims > claimCount ? maxClaims - claimCount : 0;
        _isPaused = paused;
    }

    receive() external payable {
        revert EthNotAccepted();
    }

    fallback() external payable {
        revert UnknownFunction();
    }
}
