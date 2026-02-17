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

    /// @notice Sets the reentrancy guard before function execution
    /// @dev Reverts if contract is already locked (reentrant call detected)
    function _nonReentrantBefore() internal {
        if (locked) revert ReentrancyGuardReentrantCall();
        locked = true;
    }

    /// @notice Clears the reentrancy guard after function execution
    /// @dev Must be called after _nonReentrantBefore to release the lock
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
///
/// Security Consideration - Signature Replay:
/// The signed message in the Noir circuit contains only the claimer address.
/// This means signatures could theoretically be replayed on other chains or
/// contracts using the same address derivation scheme. The DOMAIN_SEPARATOR
/// provides some protection by scoping nullifiers to this specific deployment
/// context. For multi-chain deployments, consider using a unique DOMAIN_SEPARATOR
/// per chain or upgrading to EIP-712 typed data signing.
contract Airdrop is ReentrancyGuard {
    /// @notice Domain separator for nullifier computation (bytes 28-31 of 32-byte array)
    /// @dev This constant is stored for on-chain verification purposes and documentation.
    ///      The actual nullifier computation happens in the Noir circuit, not in this contract.
    ///      The contract only verifies that the nullifier hasn't been used before.
    ///      Must match the value in Noir circuit (main.nr) and CLI (common.rs).
    ///      Value: 0xa1b2c3d4 placed at bytes 28-31 of a 32-byte array.
    bytes4 public constant DOMAIN_SEPARATOR = 0xa1b2c3d4;

    /// @notice Half of the secp256k1 curve order (big-endian)
    /// @dev Used to validate ECDSA signature low-s values to prevent malleability.
    ///      n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    ///      This value is enforced in the Noir circuit's validate_signature_low_s function.
    ///      Included here for documentation and cross-component consistency verification.
    bytes32 public constant SECP256K1_HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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
    error ProofTooLong();
    error MaxClaimsBelowCurrent();
    error OperationExpired();
    error InvalidToken();
    error ContractPaused();
    error ContractNotPaused();
    error EthNotAccepted();
    error UnknownFunction(bytes4 selector);
    error InsufficientBalanceForWithdraw();
    error ClaimToContract();
    error InvalidNullifier();
    error EmptyBatch();
    error BatchTooLarge();
    error BatchClaimsTooLarge();
    error NoPendingOwnershipTransfer();
    error CannotRecoverAirdropToken();
    error InvalidRecoveryToken();

    address public owner;
    address public pendingOwner;
    IERC20 public token;
    IUltraVerifier public verifier;
    bytes32 public merkleRoot;
    bool public paused;

    string public constant VERSION = "1.0.0";

    /// @notice Amount of tokens distributed per claim (100 tokens with 18 decimals)
    uint256 public constant CLAIM_AMOUNT = 100 * 10 ** 18;

    /// @notice Maximum number of operations that can be cancelled in a single batch
    /// @dev Limited to 50 to prevent out-of-gas errors while allowing efficient bulk operations
    uint256 public constant MAX_BATCH_SIZE = 50;

    /// @notice Maximum number of claims that can be processed in a single batch transaction
    /// @dev Limited to 10 to balance gas efficiency with block gas limits and prevent DoS vectors.
    ///      Each claim involves a ZK proof verification which is gas-intensive.
    uint256 public constant MAX_BATCH_CLAIMS = 10;

    /// @notice Maximum length of the proof array to prevent DoS attacks
    /// @dev ZK proofs have bounded size. This prevents malicious actors from submitting
    ///      excessively large arrays that could cause out-of-gas issues.
    uint256 public constant MAX_PROOF_LENGTH = 1000;
    /// @notice Total number of tokens claimed
    uint256 public totalClaimed;
    /// @notice Total number of successful claims made
    uint256 public claimCount;
    /// @notice Maximum number of claims allowed to prevent contract draining
    uint256 public maxClaims;

    /// @notice Timelock delay for sensitive owner operations (2 days = 48 hours)
    /// @dev Provides time for users to react to malicious proposals
    uint256 public constant TIMELOCK_DELAY = 2 days;
    /// @notice Operations expire after 14 days to prevent indefinite execution
    /// @dev Forces re-scheduling of operations that weren't executed in time
    uint256 public constant TIMELOCK_EXPIRATION = 14 days;
    mapping(bytes32 => uint256) public timelockSchedule;
    mapping(bytes32 => bool) public executedOperations;
    mapping(bytes32 => bool) public cancelledOperations;

    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(address indexed recipient, bytes32 indexed nullifier, uint256 indexed claimCount, uint256 amount);
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
    event RootUpdateScheduled(
        bytes32 indexed newRoot, bytes32 indexed operationHash, uint256 executeAfter
    );
    event VerifierUpdateScheduled(
        address indexed newVerifier, bytes32 indexed operationHash, uint256 executeAfter
    );
    event MaxClaimsUpdateScheduled(
        uint256 newMaxClaims, bytes32 indexed operationHash, uint256 executeAfter
    );
    event WithdrawalScheduled(uint256 amount, bytes32 indexed operationHash, uint256 executeAfter);
    event RenounceOwnershipScheduled(bytes32 indexed operationHash, uint256 executeAfter);
    event BatchClaimed(address indexed recipient, uint256 indexed claimCount, uint256 totalAmount);
    event BatchOperationsCancelled(bytes32[] indexed operationHashes, uint256 count);
    event BatchOperationsScheduled(
        bytes32[] indexed operationHashes, uint256 count, uint256 executeAfter
    );
    event EmergencyTokenRecoveryScheduled(
        address indexed token, uint256 amount, bytes32 indexed operationHash, uint256 executeAfter
    );
    event EmergencyTokenRecovered(address indexed token, uint256 amount);

    enum OperationStatus {
        NotScheduled,
        Scheduled,
        Executed,
        Cancelled,
        Expired
    }

    struct ClaimInfo {
        address token;
        bytes32 merkleRoot;
        uint256 claimAmount;
        uint256 totalClaimed;
        uint256 claimCount;
        uint256 maxClaims;
        uint256 remainingClaims;
        bool isPaused;
    }

    modifier whenNotPaused() {
        _checkNotPaused();
        _;
    }

    modifier whenPaused() {
        _checkPaused();
        _;
    }

    /// @notice Internal function to check if contract is not paused
    /// @dev Reverts with ContractPaused if paused
    function _checkNotPaused() internal view {
        if (paused) revert ContractPaused();
    }

    /// @notice Internal function to check if contract is paused
    /// @dev Reverts with ContractNotPaused if not paused
    function _checkPaused() internal view {
        if (!paused) revert ContractNotPaused();
    }

    /// @notice Validates that an address contains deployed code
    /// @param addr Address to check
    /// @return True if the address contains code
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
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
        if (!_isContract(_token)) revert InvalidToken();
        if (!_isContract(_verifier)) revert InvalidVerifier();
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

    /// @notice Internal function to verify caller is owner
    /// @dev Reverts with NotOwner if caller is not the owner
    function _onlyOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    /// @notice Hashes operation data for timelock scheduling
    /// @param data The encoded operation data
    /// @return result The keccak256 hash of the operation data
    function _hashOperation(bytes memory data) internal pure returns (bytes32 result) {
        result = keccak256(data);
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
        if (pendingOwner == address(0)) revert NoPendingOwnershipTransfer();
        if (msg.sender != pendingOwner) revert NotOwner();
        address previousOwner = owner;
        owner = pendingOwner;
        delete pendingOwner;
        emit OwnershipTransferred(previousOwner, owner);
    }

    /// @notice Renounces ownership permanently
    /// @dev Sets owner to address(0). This is irreversible.
    /// Only callable via timelock for safety.
    function renounceOwnership() external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("renounceOwnership"));
        _executeTimelockedOperation(operationHash);
        address previousOwner = owner;
        owner = address(0);
        delete pendingOwner;
        emit OwnershipTransferred(previousOwner, address(0));
    }

    /// @notice Schedules ownership renunciation
    /// @dev Must be called before renounceOwnership. Subject to 2-day timelock.
    function scheduleRenounceOwnership() external onlyOwner {
        bytes32 operationHash = _hashOperation(abi.encode("renounceOwnership"));
        _scheduleOperation(operationHash);
        emit RenounceOwnershipScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Schedules a Merkle root update
    /// @param newRoot The new Merkle root to set
    /// @dev Must be called before updateRoot. Subject to 2-day timelock.
    function scheduleUpdateRoot(bytes32 newRoot) external onlyOwner {
        if (newRoot == bytes32(0)) revert InvalidRoot();
        bytes32 operationHash = _hashOperation(abi.encode("updateRoot", newRoot));
        _scheduleOperation(operationHash);
        emit RootUpdateScheduled(newRoot, operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Schedules a verifier contract update
    /// @param newVerifier Address of the new verifier contract
    /// @dev Must be called before updateVerifier. Subject to 2-day timelock.
    function scheduleUpdateVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidVerifier();
        if (!_isContract(newVerifier)) revert InvalidVerifier();
        bytes32 operationHash = _hashOperation(abi.encode("updateVerifier", newVerifier));
        _scheduleOperation(operationHash);
        emit VerifierUpdateScheduled(newVerifier, operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Schedules a max claims update
    /// @param _maxClaims New maximum claims value
    /// @dev Must be called before setMaxClaims. Subject to 2-day timelock.
    function scheduleSetMaxClaims(uint256 _maxClaims) external onlyOwner {
        if (_maxClaims == 0) revert InvalidMaxClaims();
        if (_maxClaims < claimCount) revert MaxClaimsBelowCurrent();
        bytes32 operationHash = _hashOperation(abi.encode("setMaxClaims", _maxClaims));
        _scheduleOperation(operationHash);
        emit MaxClaimsUpdateScheduled(_maxClaims, operationHash, block.timestamp + TIMELOCK_DELAY);
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
        if (proof.length > MAX_PROOF_LENGTH) revert ProofTooLong();

        uint256 currentClaimCount = claimCount;
        uint256 currentMaxClaims = maxClaims;
        if (currentClaimCount >= currentMaxClaims) revert MaxClaimsExceeded();

        IERC20 token_ = token;
        if (token_.balanceOf(address(this)) < CLAIM_AMOUNT) revert InsufficientBalance();

        bytes32 merkleRoot_ = merkleRoot;
        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(merkleRoot_);
        publicInputs[1] = uint256(uint160(recipient));
        publicInputs[2] = uint256(nullifier);

        bool isValid = verifier.verify(proof, publicInputs);
        if (!isValid) revert InvalidProof();

        usedNullifiers[nullifier] = true;
        // Safety: totalClaimed is bounded by maxClaims * CLAIM_AMOUNT.
        // maxClaims is set at construction and can only increase via timelocked setMaxClaims.
        // With uint256 max, overflow is impossible: maxClaims * CLAIM_AMOUNT << 2^256.
        unchecked {
            totalClaimed += CLAIM_AMOUNT;
            ++currentClaimCount;
        }
        claimCount = currentClaimCount;

        _safeTransfer(recipient, CLAIM_AMOUNT);

        emit Claimed(recipient, nullifier, currentClaimCount, CLAIM_AMOUNT);
    }

    /// @notice Parameters for a single claim within a batch
    /// @param proof The zero-knowledge proof proving membership in the Merkle tree
    /// @param nullifier Unique identifier derived from H(private_key || domain_separator)
    /// @param recipient Address to receive the tokens
    struct ClaimParams {
        uint256[] proof;
        bytes32 nullifier;
        address recipient;
    }

    /// @notice Claims multiple tokens in a single transaction
    /// @dev Gas-efficient batch operation with pre-validation of all inputs.
    ///      Reverts if any claim in the batch would fail.
    /// @param claims Array of claim parameters, maximum MAX_BATCH_CLAIMS (10)
    function batchClaim(ClaimParams[] calldata claims) external nonReentrant whenNotPaused {
        if (claims.length == 0) revert EmptyBatch();
        if (claims.length > MAX_BATCH_CLAIMS) revert BatchClaimsTooLarge();

        uint256 currentClaimCount = claimCount;
        uint256 currentMaxClaims = maxClaims;
        // Safety: claims.length is bounded by MAX_BATCH_CLAIMS (10), so overflow is impossible
        // since currentClaimCount <= maxClaims and maxClaims is realistically bounded by
        // the total token supply which is far less than type(uint256).max - MAX_BATCH_CLAIMS
        if (currentClaimCount + claims.length > currentMaxClaims) revert MaxClaimsExceeded();

        IERC20 token_ = token;
        IUltraVerifier verifier_ = verifier;
        if (token_.balanceOf(address(this)) < CLAIM_AMOUNT * claims.length) {
            revert InsufficientBalance();
        }

        bytes32 merkleRoot_ = merkleRoot;
        uint256 batchTotal = 0;

        for (uint256 i = 0; i < claims.length;) {
            ClaimParams calldata claimParams = claims[i];

            if (claimParams.nullifier == bytes32(0)) revert InvalidNullifier();
            if (usedNullifiers[claimParams.nullifier]) revert NullifierAlreadyUsed();
            if (claimParams.recipient == address(0)) revert InvalidRecipient();
            if (claimParams.recipient == address(this)) revert ClaimToContract();
            if (claimParams.proof.length == 0) revert EmptyProof();
            if (claimParams.proof.length > MAX_PROOF_LENGTH) revert ProofTooLong();

            // Check for duplicate nullifiers within the batch.
            // Note: This O(n²) approach is acceptable since MAX_BATCH_CLAIMS is only 10.
            // Using a mapping would add storage costs that outweigh the savings for such small batches.
            for (uint256 j = 0; j < i;) {
                if (claims[j].nullifier == claimParams.nullifier) {
                    revert NullifierAlreadyUsed();
                }
                unchecked {
                    ++j;
                }
            }

            uint256[] memory publicInputs = new uint256[](3);
            publicInputs[0] = uint256(merkleRoot_);
            publicInputs[1] = uint256(uint160(claimParams.recipient));
            publicInputs[2] = uint256(claimParams.nullifier);

            bool isValid = verifier_.verify(claimParams.proof, publicInputs);
            if (!isValid) revert InvalidProof();

            usedNullifiers[claimParams.nullifier] = true;
            // Safety: currentClaimCount is bounded by maxClaims, batchTotal by batch size * CLAIM_AMOUNT
            unchecked {
                ++currentClaimCount;
                batchTotal += CLAIM_AMOUNT;
            }

            _safeTransfer(claimParams.recipient, CLAIM_AMOUNT);

            emit Claimed(claimParams.recipient, claimParams.nullifier, currentClaimCount, CLAIM_AMOUNT);

            unchecked {
                ++i;
            }
        }

        // Safety: batchTotal is bounded by MAX_BATCH_CLAIMS * CLAIM_AMOUNT which cannot overflow uint256
        unchecked {
            totalClaimed += batchTotal;
        }
        claimCount = currentClaimCount;

        emit BatchClaimed(msg.sender, claims.length, batchTotal);
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
        if (!_isContract(newVerifier)) revert InvalidVerifier();
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
        emit WithdrawalScheduled(amount, operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Internal function to withdraw tokens to owner
    /// @dev Performs the actual token transfer after timelock verification
    /// @param amount Amount of tokens to withdraw
    function _withdrawTokensInternal(uint256 amount) internal {
        if (amount > token.balanceOf(address(this))) revert InsufficientBalanceForWithdraw();
        _safeTransfer(owner, amount);
        emit TokensWithdrawn(owner, amount);
    }

    /// @notice Schedules emergency recovery of accidentally sent tokens
    /// @dev Subject to 2-day timelock. Cannot recover the airdrop token itself.
    /// @param recoveryToken Address of the token to recover
    /// @param amount Amount of tokens to recover (must be greater than 0)
    function scheduleEmergencyTokenRecovery(address recoveryToken, uint256 amount) external onlyOwner {
        if (recoveryToken == address(0)) revert InvalidRecoveryToken();
        if (recoveryToken == address(token)) revert CannotRecoverAirdropToken();
        if (!_isContract(recoveryToken)) revert InvalidRecoveryToken();
        if (amount == 0) revert InvalidMaxClaims();
        bytes32 operationHash = _hashOperation(abi.encode("emergencyRecoverToken", recoveryToken, amount));
        _scheduleOperation(operationHash);
        emit EmergencyTokenRecoveryScheduled(recoveryToken, amount, operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Executes emergency recovery of accidentally sent tokens
    /// @dev Subject to 2-day timelock. Must call scheduleEmergencyTokenRecovery first.
    /// @param recoveryToken Address of the token to recover
    /// @param amount Amount of tokens to recover
    function emergencyRecoverToken(address recoveryToken, uint256 amount) external onlyOwner {
        if (recoveryToken == address(0)) revert InvalidRecoveryToken();
        if (recoveryToken == address(token)) revert CannotRecoverAirdropToken();
        bytes32 operationHash = _hashOperation(abi.encode("emergencyRecoverToken", recoveryToken, amount));
        _executeTimelockedOperation(operationHash);
        
        (bool success, bytes memory data) =
            recoveryToken.call(abi.encodeWithSelector(IERC20.transfer.selector, owner, amount));
        if (!success) revert TransferFailed();
        if (data.length > 0 && !abi.decode(data, (bool))) revert TransferFailed();
        
        emit EmergencyTokenRecovered(recoveryToken, amount);
    }

    /// @notice Internal function for safe ERC20 token transfers
    /// @dev Uses low-level call to handle non-compliant ERC20 tokens that don't return bool
    /// @param recipient Address to receive the tokens
    /// @param amount Amount of tokens to transfer
    function _safeTransfer(address recipient, uint256 amount) internal {
        (bool success, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount));
        if (!success) revert TransferFailed();
        if (data.length > 0 && !abi.decode(data, (bool))) revert TransferFailed();
    }

    /// @notice Schedules a timelocked operation
    /// @param operationHash The hash of the operation to schedule
    /// @dev Clears any previous cancellation to allow re-scheduling.
    ///      Prevents re-scheduling of already executed operations.
    function _scheduleOperation(bytes32 operationHash) internal {
        if (timelockSchedule[operationHash] != 0) revert OperationAlreadyScheduled();
        if (executedOperations[operationHash]) revert OperationAlreadyExecuted();
        delete cancelledOperations[operationHash];
        timelockSchedule[operationHash] = block.timestamp + TIMELOCK_DELAY;
        emit TimelockScheduled(operationHash, block.timestamp + TIMELOCK_DELAY);
    }

    /// @notice Cancels a scheduled timelocked operation
    /// @param operationHash The hash of the operation to cancel
    /// @dev Only callable by owner. Cannot cancel already executed or cancelled operations.
    ///      The operation hash is computed using keccak256(abi.encode(operationName, params...)).
    function cancelOperation(bytes32 operationHash) external onlyOwner {
        if (executedOperations[operationHash]) revert OperationAlreadyExecuted();
        if (cancelledOperations[operationHash]) revert OperationAlreadyCancelled();
        if (timelockSchedule[operationHash] == 0) revert OperationNotScheduled();
        cancelledOperations[operationHash] = true;
        delete timelockSchedule[operationHash];
        emit OperationCancelled(operationHash);
    }

    /// @notice Cancels multiple scheduled timelocked operations in a single transaction
    /// @param operationHashes Array of operation hashes to cancel
    /// @dev Only callable by owner. More gas-efficient than calling cancelOperation multiple times.
    ///      Reverts if any operation cannot be cancelled (already executed, already cancelled, or not scheduled).
    ///      Maximum batch size is 50 to prevent out-of-gas issues.
    function batchCancelOperations(bytes32[] calldata operationHashes) external onlyOwner {
        if (operationHashes.length == 0) revert EmptyBatch();
        if (operationHashes.length > MAX_BATCH_SIZE) revert BatchTooLarge();

        for (uint256 i = 0; i < operationHashes.length;) {
            bytes32 opHash = operationHashes[i];
            if (executedOperations[opHash]) revert OperationAlreadyExecuted();
            if (cancelledOperations[opHash]) revert OperationAlreadyCancelled();
            if (timelockSchedule[opHash] == 0) revert OperationNotScheduled();
            cancelledOperations[opHash] = true;
            delete timelockSchedule[opHash];
            emit OperationCancelled(opHash);
            unchecked {
                ++i;
            }
        }

        emit BatchOperationsCancelled(operationHashes, operationHashes.length);
    }

    /// @notice Schedules multiple timelocked operations in a single transaction
    /// @param operationHashes Array of operation hashes to schedule
    /// @dev Only callable by owner. More gas-efficient than calling _scheduleOperation multiple times.
    ///      Reverts if any operation is already scheduled. Operations that were previously
    ///      cancelled can be re-scheduled.
    ///      Maximum batch size is 50 to prevent out-of-gas issues.
    function batchScheduleOperations(bytes32[] calldata operationHashes) external onlyOwner {
        if (operationHashes.length == 0) revert EmptyBatch();
        if (operationHashes.length > MAX_BATCH_SIZE) revert BatchTooLarge();

        uint256 executeAfter = block.timestamp + TIMELOCK_DELAY;

        for (uint256 i = 0; i < operationHashes.length;) {
            bytes32 opHash = operationHashes[i];
            if (timelockSchedule[opHash] != 0) revert OperationAlreadyScheduled();
            if (executedOperations[opHash]) revert OperationAlreadyExecuted();
            delete cancelledOperations[opHash];
            timelockSchedule[opHash] = executeAfter;
            emit TimelockScheduled(opHash, executeAfter);
            unchecked {
                ++i;
            }
        }

        emit BatchOperationsScheduled(operationHashes, operationHashes.length, executeAfter);
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
    /// @return True if the nullifier has been used, false otherwise
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Returns the current token balance of the contract
    /// @return The balance of tokens held by the contract
    function claimableBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// @notice Returns the number of remaining claims allowed
    /// @return The number of claims that can still be made
    function remainingClaims() external view returns (uint256) {
        return maxClaims > claimCount ? maxClaims - claimCount : 0;
    }

    /// @notice Returns comprehensive claim-related information
    /// @return info ClaimInfo struct containing all claim-related state
    function claimInfo() external view returns (ClaimInfo memory info) {
        info.token = address(token);
        info.merkleRoot = merkleRoot;
        info.claimAmount = CLAIM_AMOUNT;
        info.totalClaimed = totalClaimed;
        info.claimCount = claimCount;
        info.maxClaims = maxClaims;
        info.remainingClaims = maxClaims > claimCount ? maxClaims - claimCount : 0;
        info.isPaused = paused;
    }

    /// @notice Returns the status of a timelocked operation
    /// @param operationHash The hash of the operation to check
    /// @return status The current status of the operation
    function getOperationStatus(bytes32 operationHash)
        external
        view
        returns (OperationStatus status)
    {
        // Gas optimization: Check for zero hash first
        if (operationHash == bytes32(0)) {
            return OperationStatus.NotScheduled;
        }
        if (executedOperations[operationHash]) {
            return OperationStatus.Executed;
        }
        if (cancelledOperations[operationHash]) {
            return OperationStatus.Cancelled;
        }
        uint256 executeAfter = timelockSchedule[operationHash];
        if (executeAfter == 0) {
            return OperationStatus.NotScheduled;
        }
        if (block.timestamp > executeAfter + TIMELOCK_EXPIRATION) {
            return OperationStatus.Expired;
        }
        return OperationStatus.Scheduled;
    }

    /// @notice Returns the scheduled execution time for an operation
    /// @param operationHash The hash of the operation to check
    /// @return executeAfter The timestamp after which the operation can be executed (0 if not scheduled)
    function getOperationSchedule(bytes32 operationHash)
        external
        view
        returns (uint256 executeAfter)
    {
        return timelockSchedule[operationHash];
    }

    /// @notice Computes the operation hash for a root update
    /// @dev Helper function for frontends to compute operation hashes without encoding
    /// @param newRoot The new Merkle root
    /// @return The operation hash
    function getUpdateRootHash(bytes32 newRoot) external pure returns (bytes32) {
        return _hashOperation(abi.encode("updateRoot", newRoot));
    }

    /// @notice Computes the operation hash for a verifier update
    /// @dev Helper function for frontends to compute operation hashes without encoding
    /// @param newVerifier The new verifier address
    /// @return The operation hash
    function getUpdateVerifierHash(address newVerifier) external pure returns (bytes32) {
        return _hashOperation(abi.encode("updateVerifier", newVerifier));
    }

    /// @notice Computes the operation hash for a max claims update
    /// @dev Helper function for frontends to compute operation hashes without encoding
    /// @param _maxClaims The new max claims value
    /// @return The operation hash
    function getSetMaxClaimsHash(uint256 _maxClaims) external pure returns (bytes32) {
        return _hashOperation(abi.encode("setMaxClaims", _maxClaims));
    }

    /// @notice Computes the operation hash for a token withdrawal
    /// @dev Helper function for frontends to compute operation hashes without encoding
    /// @param amount The amount to withdraw
    /// @return The operation hash
    function getWithdrawTokensHash(uint256 amount) external pure returns (bytes32) {
        return _hashOperation(abi.encode("withdrawTokens", amount));
    }

    /// @notice Computes the operation hash for ownership renunciation
    /// @dev Helper function for frontends to compute operation hashes without encoding
    /// @return The operation hash
    function getRenounceOwnershipHash() external pure returns (bytes32) {
        return _hashOperation(abi.encode("renounceOwnership"));
    }

    /// @notice Pre-validates claim parameters without executing the claim
    /// @dev Useful for frontends to check if a claim would succeed before submitting.
    ///      NOTE: This function does NOT validate the ZK proof - only checks:
    ///      - Contract is not paused
    ///      - Nullifier is valid and not already used
    ///      - Recipient is valid (not zero address, not contract address)
    ///      - Max claims not exceeded
    ///      - Sufficient token balance exists
    /// @param nullifier The nullifier to validate
    /// @param recipient The recipient address to validate
    /// @return isValid True if the claim parameters are valid
    /// @return reason Error reason if invalid (empty string if valid)
    function validateClaimParams(bytes32 nullifier, address recipient)
        external
        view
        returns (bool isValid, string memory reason)
    {
        if (paused) return (false, "Contract is paused");
        if (nullifier == bytes32(0)) return (false, "Invalid nullifier");
        if (usedNullifiers[nullifier]) return (false, "Nullifier already used");
        if (recipient == address(0)) return (false, "Invalid recipient");
        if (recipient == address(this)) return (false, "Cannot claim to contract");
        if (claimCount >= maxClaims) return (false, "Max claims exceeded");
        if (token.balanceOf(address(this)) < CLAIM_AMOUNT) return (false, "Insufficient balance");
        return (true, "");
    }

    /// @notice Pre-validates batch claim parameters without executing
    /// @dev Useful for frontends to check if a batch claim would succeed.
    ///      NOTE: This function does NOT validate ZK proofs - only checks:
    ///      - Batch size is within limits (1-10 claims)
    ///      - Contract is not paused
    ///      - Max claims would not be exceeded
    ///      - Sufficient token balance exists
    ///      - All nullifiers are valid and unique (including within batch)
    ///      - All recipients are valid
    ///      - All proof lengths are within limits
    /// @param claims Array of claim parameters to validate
    /// @return isValid True if all claim parameters are valid
    /// @return reason Error reason if invalid (empty string if valid)
    function validateBatchClaimParams(ClaimParams[] calldata claims)
        external
        view
        returns (bool isValid, string memory reason)
    {
        if (claims.length == 0) return (false, "Empty batch");
        if (claims.length > MAX_BATCH_CLAIMS) return (false, "Batch too large");
        if (paused) return (false, "Contract is paused");
        if (claimCount + claims.length > maxClaims) return (false, "Max claims exceeded");
        if (token.balanceOf(address(this)) < CLAIM_AMOUNT * claims.length) {
            return (false, "Insufficient balance");
        }

        for (uint256 i = 0; i < claims.length;) {
            if (claims[i].nullifier == bytes32(0)) {
                return (false, "Invalid nullifier in batch");
            }
            if (usedNullifiers[claims[i].nullifier]) {
                return (false, "Nullifier already used in batch");
            }
            if (claims[i].recipient == address(0)) {
                return (false, "Invalid recipient in batch");
            }
            if (claims[i].recipient == address(this)) {
                return (false, "Cannot claim to contract in batch");
            }
            if (claims[i].proof.length == 0) {
                return (false, "Empty proof in batch");
            }
            if (claims[i].proof.length > MAX_PROOF_LENGTH) {
                return (false, "Proof too long in batch");
            }

            for (uint256 j = 0; j < i;) {
                if (claims[j].nullifier == claims[i].nullifier) {
                    return (false, "Duplicate nullifier in batch");
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
        return (true, "");
    }

    receive() external payable {
        revert EthNotAccepted();
    }

    fallback() external payable {
        revert UnknownFunction(msg.sig);
    }
}
