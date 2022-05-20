// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

interface IKeyringCacheUpdater {
    event UpdateCache(address userId, bytes32 admissionPolicyId, uint256[] timestamps, bytes[] signatures);

    function admissionPolicyManager() external view returns (address);

    function keyringCache() external view returns (address);

    function updateCache(
        address userId,
        bytes32 admissionPolicyId,
        uint256[] calldata timestamps,
        bytes[] calldata signatures
    ) external returns (bool success);
}
