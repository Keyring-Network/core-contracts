// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IKeyringMerkleAuthZkVerifier {
    
    error Unacceptable(string reason);

    event Deployed(
        address deployer,
        address merkleAuthProofVerifier
    );

    struct Backdoor {
        uint256[2] c1;
        uint256[2] c2;
    }

    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct MerkleAuthProof {
        Groth16Proof proof;
        Backdoor backdoor;
        uint256 root;
        uint256[2] policyDisclosures;
        uint256 tradingAddress;
        uint256[2] regimeKey;
    }

    function MERKLE_AUTH_PROOF_VERIFIER() external returns (address);

    function checkClaim(
        MerkleAuthProof calldata merkleAuthProof
    ) external view returns (bool verified);

    function checkMerkleAuthProof(
        MerkleAuthProof calldata merkleAuthProof
    ) external view returns (bool verified);
}
