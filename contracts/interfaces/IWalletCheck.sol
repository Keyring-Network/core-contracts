// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IWalletCheck {

    event SetWalletWhitelist(address admin, address wallet, bool isWhitelisted);

    function ROLE_WALLETCHECK_ADMIN() external view returns (bytes32);

    function isWhitelisted(address wallet) external view returns(bool isWhitelisted);

    function setWalletWhitelist(address wallet, bool flagged) external;
}
