// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "./IKeyringCacheUpdater.sol";

interface IKeyringSimpleCacheUpdater is IKeyringCacheUpdater {
    event Deployed(address deployer, address trustedForwarder, address keyringCache, address admissionPolicyManager_);
}
