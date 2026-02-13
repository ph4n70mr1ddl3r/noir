# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

1. **Do NOT open a public issue** - Security vulnerabilities should be reported privately
2. Email security concerns to the project maintainers
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

## Response Timeline

- Initial response: within 48 hours
- Vulnerability assessment: within 7 days
- Fix development: depends on severity
- Public disclosure: after fix is released

## Security Considerations

### Private Key Handling

- Private keys are **never** transmitted to the smart contract
- Keys are used locally to generate ZK proofs
- Keys are zeroized from memory after use in the CLI tools
- Use the `-` flag to read private keys from stdin for enhanced security

### ZK Proofs

- The nullifier prevents double-claiming
- Merkle proofs verify membership in the qualified list
- Proof validity is verified on-chain by the verifier contract

### Smart Contract

- Timelocks protect sensitive operations (2-day delay)
- Reentrancy guards protect against reentrancy attacks
- Owner-only functions are protected
- Pause functionality for emergency situations

### Best Practices

1. Always verify the Merkle root matches the expected value
2. Never share your private key
3. Verify the verifier contract address before claiming
4. Use hardware wallets for production deployments
