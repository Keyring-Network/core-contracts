// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

/**
 * @notice KeyringGuard implementation that uses immutables and presents a simplified modifier.
 */

interface IKeyringGuardImmutable {

    error Unacceptable(string reason);

    event KeyringGuardConfigured(
        address keyringCredentials,
        address policyManager,
        uint32 admissionPolicyId,
        bytes32 universeRule,
        bytes32 emptyRule
    );

    function getKeyringCredentials() external view returns (address keyringCredentials);

    function getKeyringPolicyManager() external view returns (address policyManager);

    function getKeyringAdmissionPolicyId() external view returns (uint32 admissionPolicyId);

    function getKeyringGenesisRules() external view returns (bytes32 universeRuleId, bytes32 emptyRuleId);

    function checkKeyringCompliance(address user) external returns (bool isCompliant);    
}