// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../lib/Bytes32Set.sol";
import "../access/KeyringAccessControl.sol";
import "../interfaces/IGroupRegistry.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 @notice Deploy this contract behind a TransparentUpgradeableProxy.
 */

contract GroupRegistry is IGroupRegistry, KeyringAccessControl, Initializable {
    using Bytes32Set for Bytes32Set.Set;

    bytes32 private constant ROLE_GROUP_MASTER = keccak256("role group master");
    bytes32 private constant ROLE_DEPENDENCY_MANAGER = keccak256("role dependency_manager");

    Bytes32Set.Set private groupSet;
    mapping(bytes32 => Group) private groups;
    bytes32[50] private reservedSlots;

    modifier onlyGroupMaster() {
        _checkRole(ROLE_GROUP_MASTER, _msgSender(), "GroupRegistry:onlyGroupMaster");
        _;
    }

    modifier onlyDependencyManager() {
        _checkRole(ROLE_DEPENDENCY_MANAGER, _msgSender(), "GroupRegistry:onlyDependencyManager");
        _;
    }

    modifier validateInput(string memory description, string memory uri) {
        require(bytes(description).length > 0, "GroupRegistry:createGroup: description cannot be empty");
        require(bytes(uri).length > 0, "GroupRegistry:createdGroup: uri cannot be empty");
        _;
    }

    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        emit Deployed(_msgSender(), trustedForwarder);
    }

    function init() external initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function createGroup(string memory description, string memory uri)
        external
        onlyGroupMaster
        validateInput(description, uri)
        returns (bytes32 groupId)
    {
        groupId = keccak256(abi.encodePacked(description));
        groupSet.insert(groupId, "GroupRegistry:createGroup: generated duplicated id. Try again.");
        Group storage g = groups[groupId];
        g.description = description;
        g.uri = uri;
        emit CreateGroup(_msgSender(), groupId, description, uri);
    }

    function updateGroup(
        bytes32 groupId,
        string memory description,
        string memory uri
    ) external onlyGroupMaster validateInput(description, uri) {
        require(groupSet.exists(groupId), "GroupRegistry.updateGroup: groupId not found");
        Group storage g = groups[groupId];
        g.description = description;
        g.uri = uri;
        emit UpdateGroup(_msgSender(), groupId, description, uri);
    }

    function removeGroup(bytes32 groupId) external onlyGroupMaster {
        require(
            groups[groupId].policyDependencySet.count() == 0,
            "GroupRegistry:removeGroup: cannot remove group with policy dependencies"
        );
        groupSet.remove(groupId, "GroupRegistry.removeGroup: groupId not found");
        delete groups[groupId];
        emit RemoveGroup(_msgSender(), groupId);
    }

    /*******************************************************************
     Trusted contracts MUST maintain the group policy dependencies
     *******************************************************************/

    function addDependency(bytes32 groupId, bytes32 policyId) external onlyDependencyManager {
        require(isGroup(groupId), "GroupRegistry:addDependency: groupId not found");
        Group storage g = groups[groupId];
        g.policyDependencySet.insert(policyId, "GroupRegistry:addDependency");
        emit NewGroupPolicyDependency(_msgSender(), groupId, policyId);
    }

    function removeDependency(bytes32 groupId, bytes32 policyId) external onlyDependencyManager {
        require(
            isGroupPolicyDependency(groupId, policyId),
            "GroupRegistry:removeDependency: groupId is not used by policyId"
        );
        Group storage g = groups[groupId];
        g.policyDependencySet.remove(policyId, "GroupRegistry:removeDependency");
        emit RemoveGroupPolicyDependency(_msgSender(), groupId, policyId);
    }

    /*******************************************************************
     View functions
     *******************************************************************/

    function groupCount() external view returns (uint256 count) {
        count = groupSet.count();
    }

    function groupAtIndex(uint256 index) external view returns (bytes32 groupId) {
        return groupSet.keyAtIndex(index);
    }

    function isGroup(bytes32 groupId) public view returns (bool exists) {
        exists = groupSet.exists(groupId);
    }

    function groupPolicyDependencyCount(bytes32 groupId) external view returns (uint256 count) {
        count = groups[groupId].policyDependencySet.count();
    }

    function groupPolicyDependencyAtIndex(bytes32 groupId, uint256 index) external view returns (bytes32 policyId) {
        require(
            index < groups[groupId].policyDependencySet.count(),
            "GroupRegistry:groupPolicyDependencyAtIndex: index out of range"
        );
        policyId = groups[groupId].policyDependencySet.keyAtIndex(index);
    }

    function isGroupPolicyDependency(bytes32 groupId, bytes32 policyId) public view returns (bool isIndeed) {
        isIndeed = groups[groupId].policyDependencySet.exists(policyId);
    }

    function group(bytes32 groupId) external view returns (string memory description, string memory uri) {
        Group storage g = groups[groupId];
        return (g.description, g.uri);
    }

    function roleGroupMaster() external pure returns (bytes32 role) {
        role = ROLE_GROUP_MASTER;
    }
}
