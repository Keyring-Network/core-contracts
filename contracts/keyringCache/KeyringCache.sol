// SPDX-License-Identifier: MIT

pragma solidity 0.8.12;

import "../interfaces/IKeyringCache.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 @notice Deploy this contract behind a TransparentUpgradeableProxy.
 */

contract KeyringCache is IKeyringCache, KeyringAccessControl, Initializable {

    bytes32 public constant CACHE_UPDATER = keccak256("cache updater");
    bool[50] private reservedSlots;

    // admission policy => user => updateTime
    mapping(bytes32 => mapping(address => uint256)) public override getCache;

    modifier onlyUpdater {
        _checkRole(
            CACHE_UPDATER, 
            _msgSender(),
            "KeyringCache:onlyUpdater");
        _;
    }

    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        emit Deployed(_msgSender(), trustedForwarder);
    }

    function init() external initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function setCache(bytes32 admissionPolicyId, address user) external onlyUpdater {
        getCache[admissionPolicyId][user] = block.timestamp;
        emit UpdateCache(_msgSender(), admissionPolicyId, user);
    }

}
