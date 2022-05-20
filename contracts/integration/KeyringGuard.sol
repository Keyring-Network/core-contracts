// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "../interfaces/IKeyringCache.sol";
import "../interfaces/IAdmissionPolicyManager.sol";

/**
 Inheritable contract for contracts that enforce Keyring compliance. 
 */

contract KeyringGuard {
    address public immutable keyringCache;
    address public immutable admissionPolicyManager;

    event KeyringGuardConfigured(address keyringCache, address admissionPolicyManager);

    modifier keyringCompliance(address user, bytes32 admissionPolicyId) {
        uint256 cacheTimestamp = IKeyringCache(keyringCache).getCache(admissionPolicyId, user);
        uint256 secondsToLive = IAdmissionPolicyManager(admissionPolicyManager).getTimeToLive(admissionPolicyId);
        uint256 cacheAge = block.timestamp - cacheTimestamp;
        require(cacheAge <= secondsToLive, "KeyringGuard:keyringCompliance: stale attestations or no attestations");
        _;
    }

    constructor(address keyringCache_, address admissionPolicyManager_) {
        keyringCache = keyringCache_;
        admissionPolicyManager = admissionPolicyManager_;
        emit KeyringGuardConfigured(keyringCache_, admissionPolicyManager_);
    }
}
