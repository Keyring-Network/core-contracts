// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringCredentials.sol";
import "../interfaces/IPolicyManager.sol";

/**
 * @notice Provides the core support for functions and modifiers that inspect trader compliance
 with admission policies using the credential cache. 
 */

abstract contract KeyringGuard {

    string private constant MODULE = "KeyringGuardV1";

    error Compliance(address sender, address user, string module, string method, string reason);

    /**
     * @notice Checks if the given user has a stored, fresh credential for the admission policy in the
     credential cache.
     * @dev Use static call to inspect.
     * @param user The user address, normally a trading wallet, to check.
     * @param keyringCredentials The address for the deployed KeyringCredentials contract.
     * @param policyManager The address of the deployed PolicyManager contract to rely on.
     * @param admissionPolicyId The unique identifier of a Policy.
     * @param universeRule The id of the universe (everyone) Rule.
     * @param emptyRule The id of the empty (noone) Rule.
     * @return isIndeed True if a valid credential is found and its age is less than or equal to
     the admission policy's TTL. 
     */
    function _isCompliant(
        address user,
        address keyringCredentials,
        address policyManager,
        uint32 admissionPolicyId,
        bytes32 universeRule,
        bytes32 emptyRule
    ) internal returns (bool isIndeed) {
        uint32 userPolicyId = IPolicyManager(policyManager).userPolicy(user);
        bytes32 userRuleId = IPolicyManager(policyManager).policyRuleId(userPolicyId);
        bytes32 admissionPolicyRuleId = IPolicyManager(policyManager).policyRuleId(admissionPolicyId);
        if (admissionPolicyRuleId == universeRule && userRuleId == universeRule) {
            isIndeed = true;
        } else if (admissionPolicyRuleId == emptyRule || userRuleId == emptyRule) {
            isIndeed = false;
        } else {
            uint256 timestamp = IKeyringCredentials(keyringCredentials).getCredential(
                1,
                user,
                admissionPolicyId
            );
            uint256 expiryTime = IPolicyManager(policyManager).policyTtl(admissionPolicyId);
            uint256 cacheAge = block.timestamp - timestamp;
            isIndeed = cacheAge <= expiryTime;
        }
    }
}
