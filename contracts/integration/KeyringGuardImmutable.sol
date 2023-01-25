// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "./KeyringGuard.sol";
import "../interfaces/IKeyringGuardImmutable.sol";
import "../interfaces/IRuleRegistry.sol";

/**
 * @notice KeyringGuard implementation that uses immutable configuration parameters and presents 
 a simplified modifier for use in derived contracts.
 */

abstract contract KeyringGuardImmutable is IKeyringGuardImmutable, KeyringGuard {

    string private constant MODULE = "KeyringGuardImmutable";
    address private immutable _keyringCredentials;
    address private immutable _policyManager;
    uint32 private immutable _admissionPolicyId;
    bytes32 private immutable _universeRule;
    bytes32 private immutable _emptyRule;

    address internal constant NULL_ADDRESS = address(0);
    bytes32 internal constant NULL_BYTES32 = bytes32(0);

    /**
     * @dev Use this modifier in derived contracts to enforce user compliance with the admission policy.
     * @param user User address to check.
     */
    modifier keyringCompliance(address user) {
        if (
            !_isCompliant(
                user,
                _keyringCredentials,
                _policyManager,
                _admissionPolicyId,
                _universeRule,
                _emptyRule
            )
        )
            revert Compliance({
                sender: msg.sender,
                user: user,
                module: MODULE,
                method: "keyringCompliance",
                reason: "stale credential or no credential"
            });
        _;
    }

    /**
     * @param keyringCredentials The KeyringCredentials contract to rely on.
     * @param policyManager The address of the deployed PolicyManager to rely on.
     * @param admissionPolicyId The unique identifier of a Policy against which user accounts will be compared.
     */
    constructor(
        address keyringCredentials,
        address policyManager,
        uint32 admissionPolicyId
    ) {
        if (keyringCredentials == NULL_ADDRESS)
            revert Unacceptable({
                reason: "credentials cannot be empty"
            });
        if (policyManager == NULL_ADDRESS)
            revert Unacceptable({
                reason: "policyManager cannot be empty"
            });
        if (!_isPolicy(policyManager, admissionPolicyId))
            revert Unacceptable({
                reason: "admissionPolicyId not found"
            });
        _keyringCredentials = keyringCredentials;
        _policyManager = policyManager;
        _admissionPolicyId = admissionPolicyId;
        (_universeRule, _emptyRule) = IRuleRegistry(IPolicyManager(policyManager).ruleRegistry()).genesis();
        if (_universeRule == NULL_BYTES32)
            revert Unacceptable({
                reason: "the universe rule is not defined in the PolicyManager's RuleRegistry"
            });
        if (_emptyRule == NULL_BYTES32)
            revert Unacceptable({
                reason: "the empty rule is not defined in the PolicyManager's RuleRegistry"
            });
        emit KeyringGuardConfigured(
            keyringCredentials,
            policyManager,
            admissionPolicyId,
            _universeRule,
            _emptyRule
        );
    }

    /**
     * @return keyringCredentials The KeyringCredentials contract to rely on.
     */
    function getKeyringCredentials() external view override returns (address keyringCredentials) {
        keyringCredentials = _keyringCredentials;
    }

    /**
     * @return policyManager The PolicyManager contract to rely on.
     */
    function getKeyringPolicyManager() external view override returns (address policyManager) {
        policyManager = _policyManager;
    }

    /**
     * @return admissionPolicyId The unique identifier of the admission Policy.
     */
    function getKeyringAdmissionPolicyId() external view override returns (uint32 admissionPolicyId) {
        admissionPolicyId = _admissionPolicyId;
    }

    /**
     * @return universeRuleId The id of the universal set Rule (everyone),
     * @return emptyRuleId The id of the null set Rule (no one),
     */
    function getKeyringGenesisRules() external view override returns (bytes32 universeRuleId, bytes32 emptyRuleId) {
        universeRuleId = _universeRule;
        emptyRuleId = _emptyRule;
    }

    /**
     * @notice Checks user compliance status.
     * @dev Use static call to inspect.
     * @param user User to check.
     * @return isCompliant True if the user would be permitted to proceed. 
     */
    function checkKeyringCompliance(address user) external override returns (bool isCompliant) {
        isCompliant = _isCompliant(
            user,
            _keyringCredentials,
            _policyManager,
            _admissionPolicyId,
            _universeRule,
            _emptyRule
        );
    }

    /**
     * @notice Checks the existence of a policy in the PolicyManager contract.
     * @param policyManager The address of the deployed PolicyManager contract to query.
     * @param policyId The unique identifier of a policy.
     */
    function _isPolicy(address policyManager, uint32 policyId) internal view returns (bool isIndeed) {
        isIndeed = IPolicyManager(policyManager).isPolicy(policyId);
    }      
}
