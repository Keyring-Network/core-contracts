// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IWalletCheck.sol";
import "../access/KeyringAccessControl.sol";

contract WalletCheck is IWalletCheck, KeyringAccessControl {

    bytes32 public constant override ROLE_WALLET_CHECK_ADMIN = keccak256("wallet check admin role");

    mapping(address => bool) public override isFlagged;

    modifier onlyWalletCheckAdmin() {
        _checkRole(ROLE_WALLET_CHECK_ADMIN, _msgSender(), "WalletCheck::onlyAggregator");
        _;
    }

    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function setWalletFlag(address wallet, bool flagged) external override onlyWalletCheckAdmin {
        isFlagged[wallet] = flagged;
        emit SetWalletFlag(_msgSender(), wallet, flagged);
    }

}
