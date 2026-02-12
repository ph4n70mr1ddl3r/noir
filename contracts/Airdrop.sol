// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUltraVerifier {
    function verify(uint256[] calldata _proof, uint256[] calldata _publicInputs) external view returns (bool);
}

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Airdrop {
    error NullifierAlreadyUsed();
    error InvalidProof();
    error InvalidRoot();
    error InsufficientBalance();
    error NotOwner();

    address public owner;
    IERC20 public token;
    IUltraVerifier public verifier;
    bytes32 public merkleRoot;

    uint256 public constant CLAIM_AMOUNT = 100 * 10**18; // 100 tokens per claim
    uint256 public totalClaimed;

    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(address indexed recipient, bytes32 indexed nullifier);
    event RootUpdated(bytes32 oldRoot, bytes32 newRoot);

    constructor(
        address _token,
        address _verifier,
        bytes32 _merkleRoot
    ) {
        owner = msg.sender;
        token = IERC20(_token);
        verifier = IUltraVerifier(_verifier);
        merkleRoot = _merkleRoot;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function claim(
        uint256[] calldata proof,
        bytes32 nullifier,
        address recipient
    ) external {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();

        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(merkleRoot);
        publicInputs[1] = uint256(uint160(recipient));
        publicInputs[2] = uint256(nullifier);

        bool isValid = verifier.verify(proof, publicInputs);
        if (!isValid) revert InvalidProof();

        usedNullifiers[nullifier] = true;
        totalClaimed += CLAIM_AMOUNT;

        bool success = token.transfer(recipient, CLAIM_AMOUNT);
        if (!success) revert InsufficientBalance();

        emit Claimed(recipient, nullifier);
    }

    function updateRoot(bytes32 newRoot) external onlyOwner {
        bytes32 oldRoot = merkleRoot;
        merkleRoot = newRoot;
        emit RootUpdated(oldRoot, newRoot);
    }

    function updateVerifier(address newVerifier) external onlyOwner {
        verifier = IUltraVerifier(newVerifier);
    }

    function withdrawTokens(uint256 amount) external onlyOwner {
        bool success = token.transfer(owner, amount);
        require(success, "Transfer failed");
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }
}