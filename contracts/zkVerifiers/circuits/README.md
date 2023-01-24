# ZK Verifiers

Solidity assets in this folder are generated from the Circom circuits. IdentityMembershipProofVerifier is a exact copy of https://github.com/semaphore-protocol/semaphore/blob/main/packages/contracts/contracts/verifiers/Verifier20.sol

## Exact circuit output

Where flexible pragmas are declared, Keyring uses the lowest acceptable compiler version as specified in `hardhat.config.ts`:

- 0.6.11
- 0.8.4

These are left unchanged so that these assets are exact outputs of the Circom system. 

## Depoyment ceremony

Zero-knowledge Proofs require the input of certain constants that should be generated in a demonstrably open and tamper-resistent fashion. These "ceremonies" generally involve assembling a group of participants with the mathematical guarantee that the system is resistent to cryptographic attack (in this context, an adversary acquiring the ability to reveal a secret that is meant to be confidential) provided that at least one ceremony participant is honest. 

As such, Keyring will organize and execute such a ceremory prior to deploying Keying Network in a production setting. 

The `zkVerifiers` are representative of the final code and are suitable for testing. The final, production versions of the `zkVerifiers` will be substantially the same but will differ in that certain hard-coded parameters will change following a formal launch ceremony. 
