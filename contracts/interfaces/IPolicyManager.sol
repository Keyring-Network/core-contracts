// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../lib/Bytes32Set.sol";

interface IPolicyManager {
    struct Policy {
        Bytes32Set.Set inclusionSet;
        Bytes32Set.Set exclusionSet;
    }

    event Deployed(address deployer, address trustedForwarder, address groupRegistry);
    event NewPolicy(address user, bytes32 newPolicyAndAdminRole, bytes32 userAdminRole);
    event AddPolicyInclusion(address policyAdmin, bytes32 policyId, bytes32 groupId);
    event AddPolicyExclusion(address policyAdmin, bytes32 policyId, bytes32 groupId);
    event RemovePolicyInclusion(address policyAdmin, bytes32 policyId, bytes32 groupId);
    event RemovePolicyExclusion(address policyAdmin, bytes32 policyId, bytes32 groupId);

    function groupRegistry() external view returns (address);

    function nonce() external view returns (uint256);

    function init() external;

    function setUserPolicy(bytes32 policyId) external;

    function createPolicy() external returns (bytes32 newPolicy);

    function addPolicyInclusion(bytes32 policyId, bytes32 groupId) external;

    function addPolicyExclusion(bytes32 policyId, bytes32 groupId) external;

    function removePolicyInclusion(bytes32 policyId, bytes32 groupId) external;

    function removePolicyExclusion(bytes32 policyId, bytes32 groupId) external;

    function policyCount() external view returns (uint256 count);

    function policyAtIndex(uint256 index) external view returns (bytes32 policyId);

    function isPolicy(bytes32 policyId) external view returns (bool isIndeed);

    function policyUserAdminRole(bytes32 policyId) external pure returns (bytes32 role);

    function policyInclusionCount(bytes32 policyId) external view returns (uint256 count);

    function policyExclusionCount(bytes32 policyId) external view returns (uint256 count);

    function policyInclusionGroupAtIndex(bytes32 policyId, uint256 index) external view returns (bytes32 groupId);

    function policyExclusionGroupAtIndex(bytes32 policyId, uint256 index) external view returns (bytes32 groupId);

    function isPolicyInclusionGroup(bytes32 policyId, bytes32 groupId) external view returns (bool isIndeed);

    function isPolicyExclusionGroup(bytes32 policyId, bytes32 groupId) external view returns (bool isIndeed);

    function rolePolicyAdmin() external pure returns (bytes32 role);
}
