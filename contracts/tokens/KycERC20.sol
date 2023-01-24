// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKycERC20.sol";
import "../integration/KeyringGuardImmutable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 @notice This contract illustrates how an immutable KeyringGuard can be wrapped around collateral tokens 
 (e.g. DAI Token). Tokens can only be transferred to an address that maintains compliance with the configured 
 policy.
 */

contract KycERC20 is IKycERC20, ERC20Permit, ERC20Wrapper, KeyringGuardImmutable {
    
    string private constant MODULE = "KycERC20";
    using SafeERC20 for IERC20;

    /**
     @notice Specify the token to wrap and the new name / symbol of the wrapped token - then good to go!
     @param collateralToken The contract address of the token that is to be wrapped
     @param keyringCredentials The address for the deployed KeyringCredentials contract.
     @param policyManager The address for the deployed PolicyManager contract.
     @param policyId The unique identifier of a Policy.
     @param name_ The name of the new wrapped token. Passed to ERC20.constructor to set the ERC20.name
     @param symbol_ The symbol for the new wrapped token. Passed to ERC20.constructor to set the ERC20.symbol
     */
    constructor(
        address collateralToken,
        address keyringCredentials,
        address policyManager,
        uint32 policyId,
        string memory name_,
        string memory symbol_
    )
        ERC20(name_, symbol_)
        ERC20Permit(name_)
        ERC20Wrapper(IERC20(collateralToken))
        KeyringGuardImmutable(keyringCredentials, policyManager, policyId)
    {
        if (collateralToken == NULL_ADDRESS)
            revert Unacceptable({
                reason: "collateral token cannot be empty"
            });
        if (bytes(name_).length == 0)
            revert Unacceptable({
                reason: "name_ cannot be empty"
            });
        if (bytes(symbol_).length == 0)
            revert Unacceptable({
                reason: "symbol_ cannot be empty"
            });
    }

    /**
     @notice Returns decimals based on the underlying token decimals
     @return uint8 decimals integer
     */
    function decimals() public view override(ERC20, ERC20Wrapper) returns (uint8) {
        return ERC20Wrapper.decimals();
    }

    /**
     * @notice Compliant users deposit underlying tokens and mint the same number of wrapped tokens.
     * @param account Recipient of the wrapped tokens
     * @param amount Quantity of underlying tokens from _msgSender() to exchange for wrapped tokens (to account) at 1:1
     */
    function depositFor(address account, uint256 amount)
        public
        override(IKycERC20, ERC20Wrapper)
        keyringCompliance(account)
        keyringCompliance(_msgSender())
        returns (bool)
    {
        return ERC20Wrapper.depositFor(account, amount);
    }

    /**
     * @notice Compliant users burn a number of wrapped tokens and withdraw the same number of underlying tokens.
     * @param account Recipient of the underlying tokens
     * @param amount Quantity of wrapped tokens from _msgSender() to exchange for underlying tokens (to account) at 1:1
     */
    function withdrawTo(address account, uint256 amount)
        public
        override(IKycERC20, ERC20Wrapper)
        keyringCompliance(account)
        keyringCompliance(_msgSender())
        returns (bool)
    {
        return ERC20Wrapper.withdrawTo(account, amount);
    }

    /**
     @notice Wraps the inherited ERC20.transfer function with the keyringCompliance guard.
     @param to The recipient of amount 
     @param amount The amount to be deducted from the to's allowance.
     @return bool True if successfully executed.
     */
    function transfer(address to, uint256 amount)
        public
        override(IERC20, ERC20)
        keyringCompliance(to)
        keyringCompliance(_msgSender())
        returns (bool)
    {
        return ERC20.transfer(to, amount);
    }

    /**
     @notice Wraps the inherited ERC20.transferFrom function with the keyringCompliance guard.
     @param from The sender of amount 
     @param to The recipient of amount 
     @param amount The amount to be deducted from the to's allowance.
     @return bool True if successfully executed.
     */
    function transferFrom(address from, address to, uint256 amount) 
        public 
        override(IERC20, ERC20)
        keyringCompliance(to)
        keyringCompliance(from)
        returns (bool)
    {
        return ERC20.transferFrom(from, to, amount);
    }
}
