// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringProofVerifier.sol";
import "../interfaces/IKeyringMerkleAuthZkVerifier.sol";

/**
 @notice Binds the on-chain zero-knowledge verifiers, which are generated from circuits, together and
 applies additional constraints such as requiring that users generate membership proofs and
 authorization proofs from the same identity commitments. Includes a function inspect identity
 commitments and confirm correct construction. This is presumed to occur before identity commitments
 are included in identity trees and is thus a courtesy function in service to the aggregator which is
 required to validate identity commitments submmitted by authorization wallets. 
 */

contract KeyringMerkleAuthZkVerifier is IKeyringMerkleAuthZkVerifier {
    address private constant NULL_ADDRESS = address(0);
    address public immutable override MERKLE_AUTH_PROOF_VERIFIER;

    constructor(
        address merkleAuthProofVerifier
    ) {
        if (merkleAuthProofVerifier == NULL_ADDRESS)
            revert Unacceptable({ reason: "merkleAuthProofVerifier cannot be empty" });
        MERKLE_AUTH_PROOF_VERIFIER = merkleAuthProofVerifier;
        emit Deployed(
            msg.sender,
            merkleAuthProofVerifier
        );
    }

    /**
     @notice Check membership and authorization with merkleAuth proof using circom verifier.
     @param merkleAuthProof Proof of merkle authorization.
     @return verified True if the claim is valid. 
     */
    function checkClaim(
        MerkleAuthProof calldata merkleAuthProof
    ) external view override returns (bool verified) {
        verified = checkMerkleAuthProof(merkleAuthProof);
    }

    /**
     @notice Check that the policies disclosed are included in the identity commitment.
     @param merkleAuthProof Proof of merkle authorisation as defined in IKeyringMerkleAuthZkVerifier.
     @return verified True if the trader wallet is authorised for all policies in the disclosure.
     */
    function checkMerkleAuthProof(
        MerkleAuthProof calldata merkleAuthProof
    ) public view override returns (bool verified) {
        uint256[] memory input = new uint256[](10);
        input[0] = merkleAuthProof.root;
        input[1] = merkleAuthProof.backdoor.c1[0];
        input[2] = merkleAuthProof.backdoor.c1[1];
        input[3] = merkleAuthProof.backdoor.c2[0];
        input[4] = merkleAuthProof.backdoor.c2[1];
        input[5] = merkleAuthProof.policyDisclosures[0];
        input[6] = merkleAuthProof.policyDisclosures[1];
        input[7] = merkleAuthProof.tradingAddress;
        input[8] = merkleAuthProof.regimeKey[0];
        input[9] = merkleAuthProof.regimeKey[1];
        
        verified = IKeyringProofVerifier(MERKLE_AUTH_PROOF_VERIFIER).verifyProof(
            merkleAuthProof.proof.a,
            merkleAuthProof.proof.b,
            merkleAuthProof.proof.c,
            input
        );
    }
}
