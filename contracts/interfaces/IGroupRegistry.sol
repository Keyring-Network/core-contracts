// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../lib/Bytes32Set.sol";

interface IGroupRegistry {
    struct Group {
        string description;
        string uri;
        Bytes32Set.Set policyDependencySet;
    }

    event Deployed(address deployer, address trustedForwarder);
    event CreateGroup(address admin, bytes32 groupId, string description, string uri);
    event UpdateGroup(address admin, bytes32 groupId, string description, string uri);
    event RemoveGroup(address admin, bytes32 groupId);
    event NewGroupPolicyDependency(address manager, bytes32 groupId, bytes32 policyId);
    event RemoveGroupPolicyDependency(address manager, bytes32 groupId, bytes32 policyId);

    function init() external;

    function createGroup(string memory description, string memory uri) external returns (bytes32 groupId);

    function updateGroup(
        bytes32 groupId,
        string memory description,
        string memory uri
    ) external;

    function removeGroup(bytes32 groupId) external;

    function addDependency(bytes32 groupId, bytes32 policyId) external;

    function removeDependency(bytes32 groupId, bytes32 policyId) external;

    function groupCount() external view returns (uint256 count);

    function groupAtIndex(uint256 index) external view returns (bytes32 groupId);

    function isGroup(bytes32 groupId) external view returns (bool exists);

    function groupPolicyDependencyCount(bytes32 groupId) external view returns (uint256 count);

    function groupPolicyDependencyAtIndex(bytes32 groupId, uint256 index) external view returns (bytes32 policyId);

    function isGroupPolicyDependency(bytes32 groupId, bytes32 policyId) external view returns (bool isIndeed);

    function group(bytes32 groupId) external view returns (string memory description, string memory uri);

    function roleGroupMaster() external pure returns (bytes32 role);
}
