// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringCredentials.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 @notice The KeyringCredentials holds credentials organized by user and policy. 
 The credentials are non-transferrable and are represented as timestamps. Non-zero 
 entries indicate that the required number of Verifiers signed an attestion to
 indicated that the policies are compatible and the user is compatible with 
 the policies. 
 */

contract KeyringCredentials is IKeyringCredentials, KeyringAccessControl, Initializable {
    string private constant MODULE = "KeyringCredentials";
    address private constant NULL_ADDRESS = address(0);
    bytes32 private constant ROLE_CREDENTIAL_UPDATER = keccak256("Credentials updater");

    /**
     @notice (version => user => userPolicyId => admissionPolicyId) => updateTime
     */
    mapping(uint8 => mapping(address => mapping(bytes32 => mapping(bytes32 => uint256)))) 
        public override getCredentialV1;

    /**
     @notice Revert if the message sender doesn't have the Credentials updater role.
     */
    modifier onlyUpdater() {
        _checkRole(ROLE_CREDENTIAL_UPDATER, _msgSender(), "KeyringCredentials:onlyUpdater");
        _;
    }

    /**
     @param trustedForwarder Contract address that is allowed to relay message signers.
     */
    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        if (trustedForwarder == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "trustedForwarder cannot be empty"
            });
        emit CredentialsDeployed(_msgSender(), trustedForwarder);
    }

    /**
     @notice This upgradeable contract must be initialized.
     @dev Initializer function MUST be called directly after deployment 
     because anyone can call it but overall only once.
     */
    function init() external override initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        emit CredentialsInitialized(_msgSender());
    }

    /**
     @notice This function is usually executed by a trusted and permitted contract.
     @param user The user address for the Credential update.
     @param userPolicyId The user policy for the Credential update.
     @param admissionPolicyId The unique identifier of a Policy.
     @param timestamp The timestamp established when the user requested a credential.
     */
    function setCredentialV1(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp
    ) external override onlyUpdater {
        if (timestamp >= block.timestamp)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "setCredential",
                reason: "timestamp must be in the past"
            });
        getCredentialV1[1][user][userPolicyId][admissionPolicyId] = timestamp;
        emit UpdateCredential(1, _msgSender(), user, userPolicyId, admissionPolicyId);
    }

    /**
     @return role The constant ROLE_CREDENTIAL_UPDATER.
     */
    function roleCredentialsUpdater() external pure override returns (bytes32 role) {
        role = ROLE_CREDENTIAL_UPDATER;
    }
}
