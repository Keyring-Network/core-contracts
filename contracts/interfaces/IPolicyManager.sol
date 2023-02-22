// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../lib/PolicyStorage.sol";

interface IPolicyManager {

    error Unacceptable(string reason);

    event PolicyManagerDeployed(
        address deployer, 
        address trustedForwarder, 
        address ruleRegistry);
    
    event PolicyManagerInitialized(address admin, address credentialCache);

    event CreatePolicy(
        address indexed owner,
        uint32 indexed policyId,
        PolicyStorage.PolicyScalar policyScalar,
        address[] attestors,
        address[] walletChecks,
        bytes32 policyOwnerRole,
        bytes32 policyUserAdminRole
    );

    event UpdatePolicyScalar(
        address indexed owner,
        uint32 indexed policyId,
        PolicyStorage.PolicyScalar policyScalar,
        uint256 deadline);

    event UpdatePolicyDescription(address indexed owner, uint32 indexed policyId, string description, uint256 deadline);
    
    event UpdatePolicyRuleId(address indexed owner, uint32 indexed policyId, bytes32 indexed ruleId, uint256 deadline);

    event UpdatePolicyTtl(address indexed owner, uint32 indexed policyId, uint128 ttl, uint256 deadline);

    event UpdatePolicyGracePeriod(
        address indexed owner, 
        uint32 indexed policyId, 
        uint128 gracePeriod, 
        uint256 deadline);

    event UpdatePolicyAcceptRoots(address indexed owner, uint32 indexed policyId, uint16 acceptRoots, uint256 deadline);

    event UpdatePolicyLock(address indexed owner, uint32 indexed policyId, bool locked, uint256 deadline);

    event UpdatePolicyAllowWhitelists(
        address indexed owner, 
        uint32 indexed policyId, 
        bool allowWhitelists, 
        uint256 deadline);

    event UpdatePolicyDeadline(address indexed owner, uint32 indexed policyId, uint256 deadline);

    event AddPolicyAttestors(
        address indexed owner,
        uint32 indexed policyId,
        address[] attestors,
        uint256 deadline
    );
    
    event RemovePolicyAttestors(
        address indexed owner,
        uint32 indexed policyId,
        address[] attestor,
        uint256 deadline
    );

    event AddPolicyWalletChecks(
        address indexed owner,
        uint32 indexed policyId,
        address[] walletChecks,
        uint256 deadline
    );

    event RemovePolicyWalletChecks(
        address indexed owner,
        uint32 indexed policyId,
        address[] walletChecks,
        uint256 deadline
    );

    event AdmitAttestor(address indexed admin, address indexed attestor, string uri);
    
    event UpdateAttestorUri(address indexed admin, address indexed attestor, string uri);
    
    event RemoveAttestor(address indexed admin, address indexed attestor);

    event AdmitWalletCheck(address indexed admin, address indexed walletCheck);

    event RemoveWalletCheck(address indexed admin, address indexed walletCheck);

    function ROLE_POLICY_CREATOR() external view returns (bytes32);

    function ROLE_GLOBAL_ATTESTOR_ADMIN() external view returns (bytes32);

    function ROLE_GLOBAL_WALLETCHECK_ADMIN() external view returns (bytes32);

    function ruleRegistry() external view returns (address);

    function init(address credentialCache) external;

    function createPolicy(
        PolicyStorage.PolicyScalar calldata policyScalar,
        address[] calldata attestors,
        address[] calldata walletChecks
    ) external returns (uint32 policyId, bytes32 policyOwnerRoleId, bytes32 policyUserAdminRoleId);

    function updatePolicyScalar(
        uint32 policyId,
        PolicyStorage.PolicyScalar calldata policyScalar,
        uint256 deadline
    ) external;

    function updatePolicyDescription(uint32 policyId, string memory descriptionUtf8, uint256 deadline) external;

    function updatePolicyRuleId(uint32 policyId, bytes32 ruleId, uint256 deadline) external;

    function updatePolicyTtl(uint32 policyId, uint32 ttl, uint256 deadline) external;

    function updatePolicyGracePeriod(uint32 policyId, uint32 gracePeriod, uint256 deadline) external;

    function updatePolicyAcceptRoots(uint32 policyId, uint16 acceptRoots, uint256 deadline) external;

    function updatePolicyAllowWhitelists(uint32 policyId, bool allowWhitelists,uint256 deadline) external;
    
    function updatePolicyLock(uint32 policyId, bool locked, uint256 deadline) external;

    function setDeadline(uint32 policyId, uint256 deadline) external;

    function addPolicyAttestors(uint32 policyId, address[] calldata attestors, uint256 deadline) external;

    function removePolicyAttestors(uint32 policyId, address[] calldata attestors, uint256 deadline) external;

    function addPolicyWalletChecks(uint32 policyId, address[] calldata walletChecks, uint256 deadline) external;

    function removePolicyWalletChecks(uint32 policyId, address[] calldata walletChecks, uint256 deadline) external;

    function admitAttestor(address attestor, string calldata uri) external;

    function updateAttestorUri(address attestor, string calldata uri) external;

    function removeAttestor(address attestor) external;

    function admitWalletCheck(address walletCheck) external;

    function removeWalletCheck(address walletCheck) external;

    function policy(uint32 policyId)
        external
        returns (
            PolicyStorage.PolicyScalar memory scalar,
            address[] memory attestors,
            address[] memory walletChecks,
            uint256 deadline
        );

    function policyRawData(uint32 policyId)
        external
        view
        returns(
            uint256 deadline,
            PolicyStorage.PolicyScalar memory scalarActive,
            PolicyStorage.PolicyScalar memory scalarPending,
            address[] memory attestorsActive,
            address[] memory attestorsPendingAdditions,
            address[] memory attestorsPendingRemovals,
            address[] memory walletChecksActive,
            address[] memory walletChecksPendingAdditions,
            address[] memory walletChecksPendingRemovals);

    function policyDescription(uint32 policyId) external returns (string memory description);

    function policyOwnerRole(uint32 policyId) external pure returns (bytes32 ownerRole);

    function policyRuleId(uint32 policyId) external returns (bytes32 ruleId);
    
    function policyTtl(uint32 policyId) external returns (uint128 ttl);

    function policyGracePeriod(uint32 policyId) external returns(uint128 gracePeriod);

    function policyAcceptRoots(uint32 policyId) external returns (uint16 acceptRoots);

    function policyAllowWhitelists(uint32 policyId) external returns (bool isAllowed);

    function policyLocked(uint32 policyId) external returns (bool isLocked);

    function policyDeadline(uint32 policyId) external returns (uint256 deadline);

    function policyAttestorCount(uint32 policyId) external returns (uint256 count);

    function policyAttestorAtIndex(uint32 policyId, uint256 index)
        external
        returns (address attestor);

    function policyAttestors(uint32 policyId) external returns (address[] memory attestors);

    function isPolicyAttestor(uint32 policyId, address attestor)
        external
        returns (bool isIndeed);

    function policyWalletCheckCount(uint32 policyId) external returns (uint256 count);

    function policyWalletCheckAtIndex(uint32 policyId, uint256 index)
        external
        returns (address walletCheck);

    function policyWalletChecks(uint32 policyId) external returns (address[] memory walletChecks);

    function isPolicyWalletCheck(uint32 policyId, address walletCheck)
        external
        returns (bool isIndeed);

    function policyCount() external view returns (uint256 count);

    function isPolicy(uint32 policyId) external view returns (bool isIndeed);

    function globalAttestorCount() external view returns (uint256 count);

    function globalAttestorAtIndex(uint256 index) external view returns (address attestor);

    function isGlobalAttestor(address attestor) external view returns (bool isIndeed);

    function globalWalletCheckCount() external view returns (uint256 count);

    function globalWalletCheckAtIndex(uint256 index) external view returns(address walletCheck);

    function isGlobalWalletCheck(address walletCheck) external view returns (bool isIndeed);

    function attestorUri(address attestor) external view returns (string memory);

    function hasRole(bytes32 role, address user) external view returns (bool);
  }
