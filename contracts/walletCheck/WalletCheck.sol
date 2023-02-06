// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IWalletCheck.sol";
import "../access/KeyringAccessControl.sol";

contract WalletCheck is IWalletCheck, KeyringAccessControl {

    /**
     * @notice Wallet checks are on-chain whitelists that can contain information gathered by
     off-chain processes. Policies can specify which wallet checks must be checked on a just-in-time
     basis. This contract establishes the interface that all wallet check contracts must implement. 
     Future wallet check instances may employ additional logic. There is a distinct instance of a 
     wallet check for each on-chain check. 
     */

    bytes32 public constant override ROLE_WALLET_CHECK_ADMIN = keccak256("wallet check admin role");

    mapping(address => bool) public override isWhitelisted;

    modifier onlyWalletCheckAdmin() {
        _checkRole(ROLE_WALLET_CHECK_ADMIN, _msgSender(), "WalletCheck::onlyWalletCheckAdmin");
        _;
    }

    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**
     * @notice Set the whitelisted boolean for a specific trading wallet to true or false.
     * @param wallet The subject wallet.
     * @param whitelisted True if the wallet has passed the checks represented by this contract.
     */
    function setWalletWhitelist(address wallet, bool whitelisted) external override onlyWalletCheckAdmin {
        isWhitelisted[wallet] = whitelisted;
        emit SetWalletWhitelist(_msgSender(), wallet, whitelisted);
    }

}
