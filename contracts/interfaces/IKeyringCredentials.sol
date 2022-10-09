// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IKeyringCredentials {
    error Unacceptable(address sender, string module, string method, string reason);

    event CredentialsDeployed(address deployer, address trustedForwarder);

    event CredentialsInitialized(address admin);
    
    event UpdateCredential(
        uint8 version, 
        address updater, 
        address indexed user, 
        bytes32 indexed userPolicyId, 
        bytes32 indexed admissionPolicyId);

    function init() external;

    function getCredentialV1(
        uint8 version, 
        address user, 
        bytes32 userPolicyId, 
        bytes32 admissionPolicyId
    ) external view returns (uint256);

    function setCredentialV1(
        address user,
        bytes32 userPolicyId,        
        bytes32 admissionPolicyId,
        uint256 timestamp
    ) external;

    function roleCredentialsUpdater() external pure returns (bytes32 role);
}
