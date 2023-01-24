// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IAuthorizationProofVerifier.sol";
import "../interfaces/IIdentityConstructionProofVerifier.sol";
import "../interfaces/IIdentityMembershipProofVerifier.sol";
import "../interfaces/IKeyringZkVerifier.sol";

contract KeyringZkVerifier is IKeyringZkVerifier {

    address public immutable override IDENTITY_MEMBERSHIP_PROOF_VERIFIER;
    address public immutable override IDENTITY_CONSTRUCTION_PROOF_VERIFIER;
    address public immutable override AUTHORIZATION_PROOF_VERIFIER;

    constructor(
        address identityConstructionProofVerifier,
        address membershipProofVerifier,
        address authorisationProofVerifier
    ) {
        IDENTITY_CONSTRUCTION_PROOF_VERIFIER = identityConstructionProofVerifier;
        IDENTITY_MEMBERSHIP_PROOF_VERIFIER = membershipProofVerifier;
        AUTHORIZATION_PROOF_VERIFIER = authorisationProofVerifier;
    }

    /**
     @notice Check identity construction, membership and authorization.
     @param membershipProof Proof of inclusion in an identity tree.
     @param authorisationProof Proof of policyId inclusions in the identity commitment.
     @return verified True if the claim is valid. 
     */
    function checkClaim(
        IdentityMembershipProof calldata membershipProof,
        IdentityAuthorisationProof calldata authorisationProof
    ) external view override returns (bool verified) {
        if (
            !(membershipProof.externalNullifier == authorisationProof.externalNullifier) ||
            !(membershipProof.nullifierHash == authorisationProof.nullifierHash)
        ) return false;

        if (!checkIdentityMembershipProof(membershipProof)) return false;
        if (!checkIdentityAuthorisationProof(authorisationProof)) return false;

        return true;
    }

    /**
     @notice Check correct construction of an identity commitment.
     @param constructionProof Proof of correct construction of the identity commitment.
     @param maxAddresses The maximum addresses included in the identity commitment.
     @return verified True if the proof is valid.
     */
    function checkIdentityConstructionProof(IdentityConstructionProof calldata constructionProof, uint256 maxAddresses)
        external
        view
        override
        returns (bool verified)
    {
        if (!(constructionProof.maxAddresses <= maxAddresses)) return false;

        bool valid = IIdentityConstructionProofVerifier(IDENTITY_CONSTRUCTION_PROOF_VERIFIER).verifyProof(
            constructionProof.proof.a,
            constructionProof.proof.b,
            constructionProof.proof.c,
            [constructionProof.identity, constructionProof.policyCommitment, constructionProof.maxAddresses]
        );

        if (!valid) return false;
        verified = true;
    }

    /**
     @notice Check that the identity commitment is a member of the identity tree.
     @param membershipProof Proof of membership.
     @return verified True if the identity commitment is a member of the identity tree.
     */
    function checkIdentityMembershipProof(IdentityMembershipProof calldata membershipProof)
        public
        view
        override
        returns (bool verified)
    {
        try
            IIdentityMembershipProofVerifier(IDENTITY_MEMBERSHIP_PROOF_VERIFIER).verifyProof(
                membershipProof.proof.a,
                membershipProof.proof.b,
                membershipProof.proof.c,
                [
                    membershipProof.root,
                    membershipProof.nullifierHash,
                    membershipProof.signalHash,
                    membershipProof.externalNullifier
                ]
            )
        {
            verified = true;
        } catch {
            verified = false;
        }
    }

    /**
     @notice Check if the policies disclosed are included in the identity commitment.
     @param authorisationProof Proof of authorisation.
     @return verified True if the trader wallet is authorised for all policies in the disclosure.
     */
    function checkIdentityAuthorisationProof(IdentityAuthorisationProof calldata authorisationProof)
        public
        view
        override
        returns (bool verified)
    {
        if (
            !(
                IAuthorizationProofVerifier(AUTHORIZATION_PROOF_VERIFIER).verifyProof(
                    authorisationProof.proof.a,
                    authorisationProof.proof.b,
                    authorisationProof.proof.c,
                    [
                        authorisationProof.externalNullifier,
                        authorisationProof.nullifierHash,
                        authorisationProof.policyDisclosures[0],
                        authorisationProof.policyDisclosures[1],
                        authorisationProof.tradingAddress
                    ]
                )
            )
        ) return false;

        verified = true;
    }
}
