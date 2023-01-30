// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

/**
 * @notice KeyringGuard implementation that uses immutables and presents a simplified modifier.
 */

interface IKeyringGuard {

    error Unacceptable(string reason);

    event KeyringGuardConfigured(
        address keyringCredentials,
        address policyManager,
        address userPolicies,
        uint32 admissionPolicyId,
        bytes32 universeRule,
        bytes32 emptyRule
    );

    function checkCache(address trader) external returns (bool isIndeed);

    function checkGuard(address from, address to) external returns (bool isAuthorized);
}