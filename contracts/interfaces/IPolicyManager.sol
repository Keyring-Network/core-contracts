// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../lib/AddressSet.sol";

interface IPolicyManager {
    struct Policy {
        bytes32 ruleId;
        string description;
        uint128 requiredVerifiers;
        uint128 expiryTime;
        AddressSet.Set verifierSet;
    }

    error Unacceptable(address sender, string module, string method, string reason);

    event PolicyManagerDeployed(address deployer, address trustedForwarder, address ruleRegistry_);
    
    event PolicyManagerInitialized(address admin);

    event CreatePolicy(
        address indexed owner,
        bytes32 indexed policyId,
        string description,
        bytes32 indexed ruleId,
        uint128 requiredVerifiers,
        uint128 expiryTime,
        bytes32 userAdminRole
    );

    event UpdatePolicyDescription(address indexed owner, bytes32 indexed policyId, string description);
    
    event UpdatePolicyRuleId(address indexed owner, bytes32 indexed policyId, bytes32 indexed ruleId);
    
    event UpdatePolicyRequiredVerifiers(
        address indexed owner,
        bytes32 indexed policyId,
        uint128 requiredVerifiers
    );
    
    event UpdatePolicyExpiryTime(address indexed owner, bytes32 indexed policyId, uint128 expiryTime);

    event AddPolicyVerifier(
        address indexed owner,
        bytes32 indexed policyId,
        address indexed verifier
    );
    
    event RemovePolicyVerifier(
        address indexed owner,
        bytes32 indexed policyId,
        address indexed verifier
    );
    
    event AdmitVerifier(address indexed owner, address indexed verifier, string uri);
    
    event UpdateVerifierUri(address indexed owner, address indexed verifier, string uri);
    
    event RemoveVerifier(address indexed owner, address indexed verifier);
    
    event SetUserPolicy(address indexed user, bytes32 indexed policyId);

    function userPolicy(address user) external view returns (bytes32 policyId);

    function ruleRegistry() external view returns (address);

    function verifierUri(address) external view returns (string memory);

    function nonce() external view returns (uint256);

    function init() external;

    function createPolicy(
        string calldata description,
        bytes32 ruleId,
        uint128 expiryTime
    ) external returns (bytes32 policyId);

    function createPolicyWithVerifiers(
        string calldata description,
        bytes32 ruleId,
        uint128 expiryTime,
        uint128 requiredVerifiers,
        address[] calldata verifiers
    ) external returns (bytes32 policyId);

    function updatePolicy(
        bytes32 policyId,
        string calldata description,
        bytes32 ruleId,
        uint128 requiredVerifiers,
        uint128 expiryTime
    ) external;

    function updatePolicyDescription(bytes32 policyId, string memory description) external;

    function updatePolicyRuleId(bytes32 policyId, bytes32 ruleId) external;

    function updatePolicyRequiredVerifiers(bytes32 policyId, uint128 requiredVerifiers) external;

    function updatePolicyExpiryTime(bytes32 policyId, uint128 expiryTime) external;

    function addPolicyVerifiers(bytes32 policyId, address[] calldata verifiers) external;

    function removePolicyVerifiers(bytes32 policyId, address[] calldata verifiers) external;

    function setUserPolicy(bytes32 policyId) external;

    function admitVerifier(address verifier, string memory uri) external;

    function updateVerifierUri(address verifier, string memory uri) external;

    function removeVerifier(address verifier) external;

    function policy(bytes32 policyId)
        external
        view
        returns (
            bytes32 ruleId,
            string memory description,
            uint128 requiredVerifiers,
            uint128 expiryTime,
            uint256 verifierSetCount
        );

    function policyRuleId(bytes32 policyId) external view returns (bytes32 ruleId);

    function policyDescription(bytes32 policyId) external view returns (string memory description);

    function policyRequiredVerifiers(bytes32 policyId) external view returns (uint128 minimum);

    function policyExpiryTime(bytes32 policyId) external view returns (uint128 expiryTime);

    function policyVerifierCount(bytes32 policyId) external view returns (uint256 count);

    function policyVerifierAtIndex(bytes32 policyId, uint256 index)
        external
        view
        returns (address verifier);

    function isPolicyVerifier(bytes32 policyId, address verifier)
        external
        view
        returns (bool isIndeed);

    function policyCount() external view returns (uint256 count);

    function policyAtIndex(uint256 index) external view returns (bytes32 policyId);

    function isPolicy(bytes32 policyId) external view returns (bool isIndeed);

    function verifierCount() external view returns (uint256 count);

    function verifierAtIndex(uint256 index) external view returns (address verifier);

    function isVerifier(address verifier) external view returns (bool isIndeed);

    function policyOwnerSeed() external pure returns (bytes32 seed);

    function roleGlobalVerifierAdmin() external pure returns (bytes32 role);
}
