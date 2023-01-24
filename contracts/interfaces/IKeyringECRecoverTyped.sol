// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IKeyringECRecoverTyped {

    function getSignerFromSig(
        address user,
        uint32 userPolicyId,
        uint32 admissionPolicyId,
        uint256 timestamp,
        bool isRequest,
        bytes memory signature
    ) external view returns (address signer);

    function getHashFromAttestation(
        address user,
        uint32 userPolicyId,
        uint32 admissionPolicyId,
        uint256 timestamp,
        bool isRequest
    ) external view returns (bytes32 message);
}
