// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringCredentials.sol";
import "../interfaces/IPolicyManager.sol";

/**
 * @notice Adds Keyring compliance support to derived contracts.
 * @dev Add the modifier to functions to protect.
 */

abstract contract KeyringGuardV1 {
    string private constant MODULE = "KeyringGuardV1";

    error Compliance(address sender, address user, string module, string method, string reason);

    /**
     * @dev Use this flexible modifier to enforce distinct policies on functions within the same contract.
     * @param user The User address for the Credentials update.
     * @param keyringCredentials The address for the deployed KeyringCredentials contract.
     * @param policyManager The address for the deployed PolicyManager contract.
     * @param admissionPolicyId The unique identifier of a Policy.
     * @param universeRule The id of the universe (everyone) Rule.
     * @param emptyRule The id of the empty (noone) Rule.
     */
    modifier checkKeyring(
        address user,
        address keyringCredentials,
        address policyManager,
        bytes32 admissionPolicyId,
        bytes32 universeRule,
        bytes32 emptyRule
    ) {
        if (
            !_isCompliant(user, keyringCredentials, policyManager, admissionPolicyId, universeRule, emptyRule)
        )
            revert Compliance({
                sender: msg.sender,
                user: user,
                module: MODULE,
                method: "checkKeyring",
                reason: "stale credential or no credential"
            });
        _;
    }

    /**
     * @notice Checks if the given user is Keyring Compliant.
     * @param user The User address for the Credentials update.
     * @param keyringCredentials The address for the deployed KeyringCredentials contract.
     * @param policyManager The address for the deployed PolicyManager contract.
     * @param admissionPolicyId The unique identifier of a Policy.
     * @param universeRule The id of the universe (everyone) Rule.
     * @param emptyRule The id of the empty (noone) Rule.
     */
    function _isCompliant(
        address user,
        address keyringCredentials,
        address policyManager,
        bytes32 admissionPolicyId,
        bytes32 universeRule,
        bytes32 emptyRule
    ) internal view returns (bool isIndeed) {
        bytes32 userPolicyId = IPolicyManager(policyManager).userPolicy(user);
        bytes32 userRuleId = IPolicyManager(policyManager).policyRuleId(userPolicyId);
        bytes32 admissionPolicyRuleId = IPolicyManager(policyManager).policyRuleId(admissionPolicyId);
        if (admissionPolicyRuleId == universeRule && userRuleId == universeRule) {
            isIndeed = true;
        } else if (admissionPolicyRuleId == emptyRule || userRuleId == emptyRule) {
            isIndeed = false;
        } else {
            uint256 timestamp = IKeyringCredentials(keyringCredentials).getCredentialV1(
                1,
                user,
                userPolicyId,
                admissionPolicyId
            );
            uint256 expiryTime = IPolicyManager(policyManager).policyExpiryTime(admissionPolicyId);
            uint256 cacheAge = block.timestamp - timestamp;
            isIndeed = cacheAge <= expiryTime;
        }
    }
}
