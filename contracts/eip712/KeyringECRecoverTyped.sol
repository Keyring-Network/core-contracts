// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringECRecoverTyped.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @notice This contract is inherited by the KeyringCredentialUpdater contract, in order to retrieve 
 the address of a signer from a signature via the getSignerFromSig function. Messages are signed 
 according to the EIP-712 standard for hashing and signing of typed structured data.
 */

abstract contract KeyringECRecoverTyped is IKeyringECRecoverTyped, EIP712 {
    bytes32 private constant GET_SIGNER_TYPE_HASH = keccak256(
        "Attestation(address user,bytes32 userPolicyId,bytes32 admissionPolicyId,uint256 timestamp,bool isRequest)");

    /**
     * @notice Generate the EIP712 Type Hash for Keyring attestations.
     */
    constructor() EIP712("Keyring", "1") {}

    /**
     * @notice Ecrecover the signer from the full signature of a Keyring attestation.
     * @param user The User address for the Credentials update.
     * @param userPolicyId  The unique identifier of the user Policy currently assigned.
     * @param admissionPolicyId The unique identifier of a Policy.
     * @param timestamp EVM time of the Attestation.
     * @param isRequest True if the User is requesting, False if a Verifier is signing.
     * @param signature The full signature.
     * @return signer The elliptic curve recovered address.
     */
    function getSignerFromSig(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bool isRequest,
        bytes memory signature
    ) public view override returns (address signer) {
        bytes32 msgHash = getHashFromAttestation(user, userPolicyId, admissionPolicyId, timestamp, isRequest);
        signer = ECDSA.recover(msgHash, signature);
    }

    /**
     * @notice Generate the EIP712 message hash for a Keyring attestation.
     * @param user The User address for the Credentials update.
     * @param userPolicyId  The unique identifier of the user Policy currently assigned.
     * @param admissionPolicyId The unique identifier of a Policy to compare.
     * @param timestamp EVM time of the Attestation.
     * @param isRequest True if the User is requesting, False if a Verifier is signing.
     * @return messageHash The EIP712 message hash.
     */
    function getHashFromAttestation(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bool isRequest
    ) public view override returns (bytes32 messageHash) {
        messageHash = EIP712._hashTypedDataV4(
            keccak256(
                abi.encode(
                    GET_SIGNER_TYPE_HASH,
                    user,
                    userPolicyId,
                    admissionPolicyId,
                    timestamp,
                    isRequest
                )
            )
        );
    }
}
