// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

interface IWalletCheck {

    error Unacceptable(string reason);

    event SetWalletFlag(address admin, address wallet, bool isFlagged);

    function ROLE_WALLET_CHECK_ADMIN() external view returns (bytes32);

    function isFlagged(address wallet) external view returns(bool isFlagged);

    function setWalletFlag(address wallet, bool flagged) external;
}
