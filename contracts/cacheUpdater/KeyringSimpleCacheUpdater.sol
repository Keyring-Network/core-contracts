// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../interfaces/IKeyringSimpleCacheUpdater.sol";
import "../interfaces/IAdmissionPolicyManager.sol";
import "../interfaces/IKeyringCache.sol";
import "../crypto/KeyringSignatureVerifier.sol";

/**
 Cache updaters are deployed as immutable contracts that can be replaced by UI changes. 
 Cache updaters need the ROLE_CACHE_UPDATER permission in KeyringCache.sol in order to write to the cache. 
 Deprecated cache updaters should be removed by revoking the role in KeyringCache.sol.
 */

contract KeyringSimpleCacheUpdater is IKeyringSimpleCacheUpdater, KeyringSignatureVerifier {
    address public immutable admissionPolicyManager;
    address public immutable keyringCache;

    constructor(
        address trustedForwarder,
        address keyringCache_,
        address admissionPolicyManager_
    ) KeyringSignatureVerifier(trustedForwarder) {
        admissionPolicyManager = admissionPolicyManager_;
        keyringCache = keyringCache_;
        emit Deployed(_msgSender(), trustedForwarder, keyringCache, admissionPolicyManager_);
    }

    function updateCache(
        address userId,
        bytes32 admissionPolicyId,
        uint256[] calldata timestamps,
        bytes[] calldata signatures
    ) external returns (bool success) {
        (bytes32 policyId, uint256 quorum, , ) = IAdmissionPolicyManager(admissionPolicyManager).admissionPolicy(
            admissionPolicyId
        );
        require(timestamps.length == signatures.length, "kscu:updateCache: arrays must be equal length");
        require(timestamps.length >= quorum, "kscu:updateCache: insufficient kyc signers to update cache");
        for (uint256 i = 0; i < timestamps.length; i++) {
            address signer = attestationSigner(policyId, userId, timestamps[i], signatures[i]);
            require(
                IAdmissionPolicyManager(admissionPolicyManager).isAdmissionPolicyKycSigner(admissionPolicyId, signer),
                "kscu:updateCache: signer is not an admission policy kyc signer"
            );
        }
        IKeyringCache(keyringCache).setCache(admissionPolicyId, userId);
        success = true;
        emit UpdateCache(userId, admissionPolicyId, timestamps, signatures);
    }
}
