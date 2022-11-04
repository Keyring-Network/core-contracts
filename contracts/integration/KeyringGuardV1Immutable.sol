// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "./KeyringGuardV1.sol";
import "../interfaces/IKeyringGuardV1Immutable.sol";
import "../interfaces/IRuleRegistry.sol";

/**
 * @notice KeyringGuard implementation that uses immutables and presents a simplified modifier.
 */

abstract contract KeyringGuardV1Immutable is IKeyringGuardV1Immutable, KeyringGuardV1 {
    string private constant MODULE = "KeyringGuardImmutable";
    address private immutable _keyringCredentials;
    address private immutable _policyManager;
    bytes32 private immutable _admissionPolicyId;
    bytes32 private immutable _universeRule;
    bytes32 private immutable _emptyRule;

    address internal constant NULL_ADDRESS = address(0);
    bytes32 internal constant NULL_BYTES32 = bytes32(0);

    /**
     * @dev Use this modifier to enforce distinct Policies on functions within the same contract.
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
     * @param policyManager The address for the deployed PolicyManager contract.
     * @param admissionPolicyId The unique identifier of a Policy.
     */
    constructor(
        address keyringCredentials,
        address policyManager,
        bytes32 admissionPolicyId
    ) {
        if (keyringCredentials == NULL_ADDRESS)
            revert Unacceptable({
                sender: msg.sender,
                module: MODULE,
                method: "constructor",
                reason: "credentials cannot be empty"
            });
        if (policyManager == NULL_ADDRESS)
            revert Unacceptable({
                sender: msg.sender,
                module: MODULE,
                method: "constructor",
                reason: "policyManager cannot be empty"
            });
        if (admissionPolicyId == NULL_BYTES32)
            revert Unacceptable({
                sender: msg.sender,
                module: MODULE,
                method: "constructor",
                reason: "admissionPolicyId cannot be empty"
            });
        if (!_isPolicy(policyManager, admissionPolicyId))
            revert Unacceptable({
                sender: msg.sender,
                module: MODULE,
                method: "constructor",
                reason: "admissionPolicyId not found"
            });
        _keyringCredentials = keyringCredentials;
        _policyManager = policyManager;
        _admissionPolicyId = admissionPolicyId;
        (_universeRule, _emptyRule) = IRuleRegistry(IPolicyManager(policyManager).ruleRegistry()).genesis();
        if (_universeRule == NULL_BYTES32)
            revert Unacceptable({
                sender: msg.sender,
                module: MODULE,
                method: "constructor",
                reason: "the universe rule is not defined in the PolicyManager's RuleRegistry"
            });
        if (_emptyRule == NULL_BYTES32)
            revert Unacceptable({
                sender: msg.sender,
                module: MODULE,
                method: "constructor",
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
    function getKeyringAdmissionPolicyId() external view override returns (bytes32 admissionPolicyId) {
        admissionPolicyId = _admissionPolicyId;
    }

    /**
     * @return universeRuleId The id of the universal set Rule (everyone)
     * @return emptyRuleId The id of the empty set Rule (no one)
     */
    function getKeyringGenesisRules() external view override returns (bytes32 universeRuleId, bytes32 emptyRuleId) {
        universeRuleId = _universeRule;
        emptyRuleId = _emptyRule;
    }

    function checkKeyringCompliance(address user) external view override returns (bool isCompliant) {
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
     * @notice Checks the existence of policyId in the PolicyManager contract.
     * @param policyManager The address for the deployed PolicyManager contract.
     * @param policyId The unique identifier of a Policy.
     */
    function _isPolicy(address policyManager, bytes32 policyId) internal view returns (bool isIndeed) {
        isIndeed = IPolicyManager(policyManager).isPolicy(policyId);
    }      
}
