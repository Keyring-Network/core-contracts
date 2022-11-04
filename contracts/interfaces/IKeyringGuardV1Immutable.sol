// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

/**
 * @notice KeyringGuard implementation that uses immutables and presents a simplified modifier.
 */

interface IKeyringGuardV1Immutable {

    error Unacceptable(address sender, string module, string method, string reason);

    event KeyringGuardConfigured(
        address keyringCredentials,
        address policyManager,
        bytes32 admissionPolicyId,
        bytes32 universeRule,
        bytes32 emptyRule
    );

    function getKeyringCredentials() external view returns (address keyringCredentials);

    function getKeyringPolicyManager() external view returns (address policyManager);

    function getKeyringAdmissionPolicyId() external view returns (bytes32 admissionPolicyId);

    function getKeyringGenesisRules() external view returns (bytes32 universeRuleId, bytes32 emptyRuleId);

    function checkKeyringCompliance(address user) external view returns (bool isCompliant);    
}