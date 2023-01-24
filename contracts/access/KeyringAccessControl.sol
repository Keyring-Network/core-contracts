// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/metatx/ERC2771Context.sol";

/**
* @notice This contract manages the role-based access control via _checkRole() with meaningful 
error messages if the user does not have the requested role. This Contract is inherited by the 
PolicyManager, RuleRegistry, KeyringCredentials and KeyringCredentialUpdater contract.
*/

abstract contract KeyringAccessControl is ERC2771Context, AccessControl {

    // These reservations hold space for future versions of this module
    bytes32[50] private _reservedSlots;

    error Unauthorized(
        address sender,
        string module,
        string method,
        bytes32 role,
        string reason,
        string context
    );

    /**
     * @param trustedForwarder Contract address that is allowed to relay message signers.
     */
    constructor(address trustedForwarder) ERC2771Context(trustedForwarder) {}

    /**
     * @notice Role-based access control
     * @dev Revert if account is missing role
     * @param role Verify the account has this role
     * @param account A DeFi address to check for the role
     * @param context The function that requested the permission check
     */
    function _checkRole(
        bytes32 role,
        address account,
        string memory context
    ) internal view {
        if (!hasRole(role, account))
            revert Unauthorized({
                sender: account,
                module: "KeyringAccessControl",
                method: "_checkRole",
                role: role,
                reason: "sender does not have the required role",
                context: context
            });
    }

    /**
     * @notice Returns ERC2771 signer if msg.sender is a trusted forwarder, otherwise returns msg.sender.
     * @return sender User deemed to have signed the transaction.
     */
    function _msgSender()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (address sender)
    {
        return ERC2771Context._msgSender();
    }

    /**
     * @notice Returns msg.data if not from a trusted forwarder,
     * or truncated msg.data if the signer was appended to msg.data
     * @return data Data deemed to be the msg.data
     */
    function _msgData()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (bytes calldata)
    {
        return ERC2771Context._msgData();
    }
}
