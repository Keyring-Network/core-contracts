// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockProtocol {
    using SafeERC20 for IERC20;

    error BalanceErr();
    error AllowanceErr();

    function invest(IERC20 token, uint256 amount) external {
        // --------> keyring code goes here <--------

        if(token.balanceOf(msg.sender) < amount) revert BalanceErr();
        if(token.allowance(msg.sender, address(this)) < amount) revert AllowanceErr();
        token.safeTransferFrom(msg.sender, address(this), amount);
        // do stuff
    }
}
