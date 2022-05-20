// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../lib/AddressSet.sol";

interface IAdmissionPolicyManager {
    struct AdmissionPolicy {
        bytes32 policyId;
        uint256 quorum;
        uint256 secondsToLive;
        AddressSet.Set kycSignerSet;
    }

    event Deployed(address deployer, address trustedForwarder, address policyManager_);
    event CreateAdmissionPolicy(
        address user,
        bytes32 admissionPolicyId,
        bytes32 policyId,
        uint256 quorum,
        uint256 secondsToLive,
        bytes32 userAdminPolicy
    );
    event UpdateAdmissionPolicy(
        address user,
        bytes32 admissionPolicyId,
        bytes32 policyId,
        uint256 quorum,
        uint256 secondsToLive
    );
    event RemoveAdmissionPolicy(address user, bytes32 admissionPolicyId);
    event AddAdmissionPolicyKycSigner(address user, bytes32 admissionPolicyId, address kycSigner);
    event RemoveAdmissionPolicyKycSigner(address user, bytes32 admissionPolicyId, address kycSigner);
    event AdmitKycSigner(address admin, address kycSigner);
    event RemoveKycSigner(address admin, address kycSigner);

    function policyManager() external view returns (address);

    function nonce() external view returns (uint256);

    function init() external;

    function createAdmissionPolicy(
        bytes32 policyId,
        uint256 quorum,
        uint256 secondsToLive
    ) external returns (bytes32 admissionPolicyId);

    function updateAdmissionPolicy(
        bytes32 admissionPolicyId,
        bytes32 policyId,
        uint256 quorum,
        uint256 secondsToLive
    ) external;

    function removeAdmissionPolicy(bytes32 admissionPolicyId) external;

    function addAdmissionPolicyKycSigner(bytes32 admissionPolicyId, address kycSigner) external;

    function removeAdmissionPolicyKycSigner(bytes32 admissionPolicyId, address kycSigner) external;

    function admitKycSigner(address kycSigner) external;

    function removeKycSigner(address kycSigner) external;

    function admissionPolicy(bytes32 admissionPolicyId)
        external
        view
        returns (
            bytes32 policyId,
            uint256 quorum,
            uint256 secondsToLive,
            uint256 keySignerCount
        );

    function getTimeToLive(bytes32 admissionPolicyId) external view returns (uint256 secondsToLive);

    function getQuorum(bytes32 admissionPolicyId) external view returns (uint256 minimum);

    function admissionPolicyCount() external view returns (uint256 count);

    function admissionPolicyAtIndex(uint256 index) external view returns (bytes32 admissionPolicyId);

    function isAdmissionPolicy(bytes32 admissionPolicyId) external view returns (bool isIndeed);

    function admissionPolicyUserAdminRole(bytes32 admissionPolicyId) external view returns (bytes32 role);

    function kycSignerCount() external view returns (uint256 count);

    function kycSignerAtIndex(uint256 index) external view returns (address kycSigner);

    function isKycSigner(address kycSigner) external view returns (bool isIndeed);

    function admissionPolicyKycSignerAtIndex(bytes32 admissionPolicyId, uint256 index)
        external
        view
        returns (address kycSigner);

    function isAdmissionPolicyKycSigner(bytes32 admissionPolicyId, address kycSigner)
        external
        view
        returns (bool isIndeed);

    function roleAdmissionPolicyManager() external pure returns (bytes32 role);

    function roleKycAdmin() external pure returns (bytes32 role);
}
