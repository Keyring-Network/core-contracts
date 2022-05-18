// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

import "../interfaces/IKeyringSimpleCacheUpdater.sol";
import "../interfaces/IAdmissionPolicyManager.sol";
import "../interfaces/IKeyringCache.sol";
import "../crypto/KeyringSignatureVerifier.sol";

contract KeyringSimpleCacheUpdater is IKeyringSimpleCacheUpdater, KeyringSignatureVerifier {

    address public immutable admissionPolicyManager;
    address public immutable keyringCache;

    constructor(address trustedForwarder, address keyringCache_, address admissionPolicyManager_) 
        KeyringSignatureVerifier(trustedForwarder) 
    {
        admissionPolicyManager = admissionPolicyManager_;
        keyringCache = keyringCache_;
        emit Deployed(_msgSender(), trustedForwarder, keyringCache, admissionPolicyManager_);
    }

    function updateCache(
        address userId, 
        bytes32 admissionPolicyId, 
        uint256[] calldata timestamps, 
        bytes[] calldata signatures
    ) 
        external 
        returns(bool success) 
    {
        (bytes32 policyId, uint256 quorum, /* secondsToLive */, /* uint256 kycSignerCount */) = IAdmissionPolicyManager(admissionPolicyManager).admissionPolicy(admissionPolicyId);
        require(
            timestamps.length == signatures.length,
            "KeyringSimpleCacheUpdater:updateCache: arrays must be equal length");
        require(
            timestamps.length >= quorum,
            "KeyringSimpleCacheUpdater:updateCache: insufficient kyc signers to update cache");
        for(uint256 i=0; i<timestamps.length; i++) {
            address signer = attestationSigner(policyId, userId, timestamps[i], signatures[i]);
            require(
                IAdmissionPolicyManager(admissionPolicyManager).isAdmissionPolicyKycSigner(admissionPolicyId, signer),
                "KeyringSimpleCacheUpdater:updateCache: signer is not an admission policy kyc signer");
        }
        IKeyringCache(keyringCache).setCache(admissionPolicyId, userId);
        success = true;
    }

}
