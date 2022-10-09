// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IKeyringCredentialUpdater {
    error CanUpdateCredential(
        address sender,
        string module,
        string method,
        bytes signature,
        string reason
    );
    error Unacceptable(address sender, string module, string method, string reason);

    event CredentialUpdaterDeployed(
        address deployer,
        address trustedForwarder,
        address keyringCache,
        address admissionPolicyManager_
    );
    event AcceptCredentialUpdate(
        address indexed user,
        bytes32 indexed userPolicyId,
        bytes32 indexed admissionPolicyId,
        uint256 timestamp,
        bytes[] signatures
    );

    function updateCredential(
        address user,
        bytes32 userPolicyId,        
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bytes[] calldata signatures
    ) external;

    function canUpdateCredential(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bytes calldata signature
    ) external view returns (bool canIndeed, address signer);

    function getPolicyManager() external view returns (address policyManagerAddress);

    function getKeyringCredentials() external view returns (address credentialsAddress);
}
