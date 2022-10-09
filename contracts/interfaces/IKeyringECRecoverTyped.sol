// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IKeyringECRecoverTyped {
    function getSignerFromSig(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bool isRequest,
        bytes memory signature
    ) external view returns (address signer);

    function getHashFromAttestation(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bool isRequest
    ) external view returns (bytes32 message);
}
