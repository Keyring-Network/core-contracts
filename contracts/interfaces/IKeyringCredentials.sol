// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IKeyringCredentials {
    
    error Unacceptable(string reason);

    event CredentialsDeployed(address deployer, address trustedForwarder, address policyManager);

    event CredentialsInitialized(address admin);

    event TearDownAdmissionPolicyCredentials(address sender, uint32 policyId);

    event UpdateCredential(
        uint8 version, 
        address updater, 
        address indexed trader, 
        uint32 indexed admissionPolicyId,
        uint256 admissionPolicyEpoch);

    function ROLE_CREDENTIAL_UPDATER() external view returns (bytes32);

    function init() external;

    function tearDownAdmissionPolicyCredentials(uint32 policyId) external;

    function resetPolicyCredentials(uint32 policyId) external;

    function cache(
        uint8 version, 
        address trader, 
        uint32 admissionPolicyId,
        uint256 admissionPolicyEpoch
    ) external view returns (uint256);

    function setCredential(
        address trader,  
        uint32 admissionPolicyId,
        uint256 timestamp
    ) external;

    function getCredential(
        uint8 version, 
        address trader, 
        uint32 admissionPolicyId
    ) external view returns (uint256);
}
