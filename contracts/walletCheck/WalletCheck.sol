// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IWalletCheck.sol";
import "../access/KeyringAccessControl.sol";

contract WalletCheck is IWalletCheck, KeyringAccessControl {

    /**
     * @notice Wallet checks are on-chain blacklists that can contain information gathered by
     off-chain processes. Policies can specify which wallet checks must be check on a just-in-time
     basis when trading wallet credentials are refreshed. This contract establishes the interface
     that all wallet check contracts must implement. Future wallet check instances may employ
     additional logic. There is a distinct instance of a wallet check for each case. 
     */

    bytes32 public constant override ROLE_WALLET_CHECK_ADMIN = keccak256("wallet check admin role");

    mapping(address => bool) public override isFlagged;

    modifier onlyWalletCheckAdmin() {
        _checkRole(ROLE_WALLET_CHECK_ADMIN, _msgSender(), "WalletCheck::onlyAggregator");
        _;
    }

    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**
     * @notice Set the flagged boolean for a specific trading wallet to true or false.
     * @param wallet The subject wallet.
     * @param flagged True if the wallet is to prevent from trading for policies that 
     observe this instance. 
     */
    function setWalletFlag(address wallet, bool flagged) external override onlyWalletCheckAdmin {
        isFlagged[wallet] = flagged;
        emit SetWalletFlag(_msgSender(), wallet, flagged);
    }

}
