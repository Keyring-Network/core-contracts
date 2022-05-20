// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../interfaces/IPolicyManager.sol";
import "../interfaces/IGroupRegistry.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 @notice Deploy this contract behind a TransparentUpgradeableProxy.
 */

contract PolicyManager is IPolicyManager, KeyringAccessControl, Initializable {
    bytes32 private constant ROLE_POLICY_ADMIN = keccak256("role policy admin");

    using Bytes32Set for Bytes32Set.Set;

    Bytes32Set.Set private policySet;
    address public immutable groupRegistry;
    mapping(bytes32 => Policy) private policies;
    uint256 public nonce;

    mapping(address => bytes32) public userPolicies;

    bytes32[50] private reservedSlots;

    modifier onlyPolicyAdmin(bytes32 policy) {
        _checkRole(policy, _msgSender(), "PolicyManager:onlyPolicyAdmin");
        _;
    }

    modifier isGroup(bytes32 groupId) {
        require(IGroupRegistry(groupRegistry).isGroup(groupId), "PolicyManager:isGroup: groupId not found");
        _;
    }

    constructor(address trustedForwarder, address groupRegistry_) KeyringAccessControl(trustedForwarder) {
        groupRegistry = groupRegistry_;
        emit Deployed(_msgSender(), trustedForwarder, groupRegistry_);
    }

    /**********************************************************
     Keyring has a super-admin role and can self-assign to
     any policy admin role in an emergency.
     This privilege can be transferred or irreversibly renounced.
     **********************************************************/

    function init() external initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**********************************************************
     Users select their own policy.
     (Protocols select policyId to enforce externally)
     **********************************************************/

    function setUserPolicy(bytes32 policyId) external {
        require(isPolicy(policyId), "PolicyManager:setUserPolicy: policyId not found");
        userPolicies[_msgSender()] = policyId;
        // todo emit
    }

    /**********************************************************
     Anyone can create a policy, and they receive two roles:
       1. can manage the role
       2. can manager users who can manage the role
     **********************************************************/

    function createPolicy() external returns (bytes32 policyId) {
        nonce++;
        policyId = keccak256(abi.encodePacked(nonce, address(this)));
        bytes32 adminRole = policyUserAdminRole(policyId);
        policySet.insert(policyId, "PolicyManager:createPolicy");
        _setupRole(policyId, _msgSender());
        _setupRole(adminRole, _msgSender());
        _setRoleAdmin(policyId, adminRole);
        emit NewPolicy(_msgSender(), policyId, adminRole);
    }

    // Policies can be reconfigured, but they cannot be destroyed

    /**********************************************************
     User-definable policies
     **********************************************************/

    function addPolicyInclusion(bytes32 policyId, bytes32 groupId) external onlyPolicyAdmin(policyId) isGroup(groupId) {
        Policy storage p = policies[policyId];
        p.inclusionSet.insert(groupId, "PolicyManager:addPolicyInclusion");
        emit AddPolicyInclusion(_msgSender(), policyId, groupId);
        IGroupRegistry(groupRegistry).addDependency(groupId, policyId);
    }

    function addPolicyExclusion(bytes32 policyId, bytes32 groupId) external onlyPolicyAdmin(policyId) isGroup(groupId) {
        Policy storage p = policies[policyId];
        p.exclusionSet.insert(groupId, "PolicyManager:addPolicyExclusion");
        emit AddPolicyExclusion(_msgSender(), policyId, groupId);
        IGroupRegistry(groupRegistry).addDependency(groupId, policyId);
    }

    function removePolicyInclusion(bytes32 policyId, bytes32 groupId) external onlyPolicyAdmin(policyId) {
        Policy storage p = policies[policyId];
        p.inclusionSet.remove(groupId, "PolicyManager.removePolicyInclusion");
        emit RemovePolicyInclusion(_msgSender(), policyId, groupId);
        IGroupRegistry(groupRegistry).removeDependency(groupId, policyId);
    }

    function removePolicyExclusion(bytes32 policyId, bytes32 groupId) external onlyPolicyAdmin(policyId) {
        Policy storage p = policies[policyId];
        p.exclusionSet.remove(groupId, "PolicyManager.removePolicyExclusion");
        emit RemovePolicyExclusion(_msgSender(), policyId, groupId);
        IGroupRegistry(groupRegistry).removeDependency(groupId, policyId);
    }

    /**********************************************************
     VIEW FUNCTIONS
     **********************************************************/

    function policyCount() public view returns (uint256 count) {
        count = policySet.count();
    }

    function policyAtIndex(uint256 index) external view returns (bytes32 policyId) {
        require(index < policyCount(), "PolicyRegistry.policyAtIndex: index out of range");
        policyId = policySet.keyAtIndex(index);
    }

    function isPolicy(bytes32 policyId) public view returns (bool isIndeed) {
        isIndeed = policySet.exists(policyId);
    }

    function policyUserAdminRole(bytes32 policyId) public pure returns (bytes32 role) {
        role = keccak256(abi.encodePacked(policyId, ROLE_POLICY_ADMIN));
    }

    function policyInclusionCount(bytes32 policyId) public view returns (uint256 count) {
        count = policies[policyId].inclusionSet.count();
    }

    function policyExclusionCount(bytes32 policyId) public view returns (uint256 count) {
        count = policies[policyId].exclusionSet.count();
    }

    function policyInclusionGroupAtIndex(bytes32 policyId, uint256 index) external view returns (bytes32 groupId) {
        require(
            index < policyInclusionCount(policyId),
            "PolicyManager:policyInclusionGroupAtIndex: index out of range"
        );
        groupId = policies[policyId].inclusionSet.keyAtIndex(index);
    }

    function policyExclusionGroupAtIndex(bytes32 policyId, uint256 index) external view returns (bytes32 groupId) {
        require(
            index < policyExclusionCount(policyId),
            "PolicyManager:policyExclusionGroupAtIndex: index out of range"
        );
        groupId = policies[policyId].exclusionSet.keyAtIndex(index);
    }

    function isPolicyInclusionGroup(bytes32 policyId, bytes32 groupId) external view returns (bool isIndeed) {
        isIndeed = policies[policyId].inclusionSet.exists(groupId);
    }

    function isPolicyExclusionGroup(bytes32 policyId, bytes32 groupId) external view returns (bool isIndeed) {
        isIndeed = policies[policyId].exclusionSet.exists(groupId);
    }

    function rolePolicyAdmin() external pure returns (bytes32 role) {
        role = ROLE_POLICY_ADMIN;
    }
}
