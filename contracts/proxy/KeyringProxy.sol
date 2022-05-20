// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.12;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract KeyringProxy is TransparentUpgradeableProxy {
    // solhint-disable no-empty-blocks
    constructor(
        address _logic,
        address admin_,
        bytes memory _data
    ) TransparentUpgradeableProxy(_logic, admin_, _data) {}
}
