// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "./IKeyringMerkleAuthZkVerifier.sol";

interface IKeyringMerkleAuthZkCredentialUpdater {
    
    event CredentialUpdaterDeployed(
        address deployer,
        address trustedForwarder,
        address keyringCache,
        address admissionPolicyManager,
        address keyringMerkleAuthZkVerifier
    );

    event AdmitIdentityTree(address admin, address identityTree);

    event RemoveIdentityTree(address admin, address identityTree);

    event AcceptCredentialUpdate(
        address sender, 
        address trader, 
        IKeyringMerkleAuthZkVerifier.MerkleAuthProof merkleAuthProof, 
        uint256 rootTime);

    function POLICY_MANAGER() external view returns (address);
    function KEYRING_CREDENTIALS() external view returns (address);
    function KEYRING_MERKLE_AUTH_ZK_VERIFIER() external view returns (address);

    function updateCredentials(
        address attestor,
        IKeyringMerkleAuthZkVerifier.MerkleAuthProof calldata merkleAuthProof
    ) external;

    function checkPolicy( 
        uint32 policyId, 
        address attestor
    ) external returns (bool acceptable);

    function pack12x20(uint32[12] calldata input) external pure returns (uint256 packed);

    function unpack12x20(uint256 packed) external pure returns (uint32[12] memory unpacked);
 
}
