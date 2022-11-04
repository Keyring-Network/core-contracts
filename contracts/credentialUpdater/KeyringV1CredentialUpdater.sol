// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringCredentialUpdater.sol";
import "../interfaces/IPolicyManager.sol";
import "../interfaces/IKeyringCredentials.sol";
import "../access/KeyringAccessControl.sol";
import "../eip712/KeyringECRecoverTyped.sol";

/**
 * @notice This contract acts as a Credentials Updater, which needs to have ROLE_CREDENTIAL_UPDATER 
 permission in the KeyringCredentials contract in order to record Credentials. The contract checks 
 signatures via the getSignerFromSig function and therefore enforces the protocol.
 */

contract KeyringV1CredentialUpdater is
    IKeyringCredentialUpdater,
    KeyringECRecoverTyped,
    KeyringAccessControl
{
    string private constant MODULE = "KeyringV1CredentialUpdater";
    address private constant NULL_ADDRESS = address(0);
    address private immutable _policyManager;
    address private immutable _keyringCredentials;

    /**
     * @param trustedForwarder Contract address that is allowed to relay message signers.
     * @param keyringCredentials The address for the deployed {KeyringCredentials} contract.
     * @param policyManager The address for the deployed PolicyManager contract.
     */
    constructor(
        address trustedForwarder,
        address keyringCredentials,
        address policyManager
    ) KeyringAccessControl(trustedForwarder) {
        if (trustedForwarder == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "trustedForwarder cannot be empty"
            });
        if (keyringCredentials == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "keyringCredentials cannot be empty"
            });
        if (policyManager == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "policyManager cannot be empty"
            });
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _policyManager = policyManager;
        _keyringCredentials = keyringCredentials;
        emit CredentialUpdaterDeployed(
            _msgSender(),
            trustedForwarder,
            keyringCredentials,
            policyManager
        );
    }

    /**
     * @notice The Credential Updater role can update the keyring Credentials
     * for the User and Policy subject to valid timestamps and signatures.
     * @param admissionPolicyId The unique identifier of a Policy.
     * @param user The User address for the Credentials update.
     * @param userPolicyId The unique identifier of a Policy.
     * @param timestamp Timestamp of the credential request.
     * @param signatures Array of signatures which functions as an attestation bundle
     * coming from verifiers that attest a credential by signing a certain message.
     */
    function updateCredential(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bytes[] calldata signatures
    ) external override {
        address lastVerifier;
        IPolicyManager a = IPolicyManager(_policyManager);
        uint256 requiredVerifiers = a.policyRequiredVerifiers(admissionPolicyId);
        bytes32 userPolicyId_ = IPolicyManager(_policyManager).userPolicy(user);
        
        if(userPolicyId_ != userPolicyId) {
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateCredential",
                reason: "incorrect userPolicyId"
            });
        }
        if (timestamp > block.timestamp)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateCredential",
                reason: "timestamp must be in the past"
            });
        if (signatures.length < requiredVerifiers)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateCredential",
                reason: "insufficient signatures to update Credential"
            });
        if (requiredVerifiers == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateCredential",
                reason: "credentials are not created when requiredVerifiers is set to 0"
            });

        for (uint256 i = 0; i < signatures.length; i++) {
            (bool canUpdate, address verifier) = canUpdateCredential(
                user,
                userPolicyId,
                admissionPolicyId,
                timestamp,
                signatures[i]
            );

            if (uint160(verifier) <= uint160(lastVerifier))
                revert Unacceptable({
                    sender: _msgSender(),
                    module: MODULE,
                    method: "updateCredential",
                    reason: "verifier addresses from signatures must be sorted in ascending order"
                });
            if (!canUpdate)
                revert CanUpdateCredential({
                    sender: _msgSender(),
                    module: MODULE,
                    method: "updateCredential",
                    signature: signatures[i],
                    reason: "signature unacceptable or expired"
                });
            lastVerifier = verifier;
        }
        emit AcceptCredentialUpdate(user, userPolicyId, admissionPolicyId, timestamp, signatures);
        IKeyringCredentials(_keyringCredentials).setCredentialV1(user, userPolicyId, admissionPolicyId, timestamp);
    }

    /**
     * @param user The User address for the Credentials update.
     * @param userPolicyId The policy set by the user.
     * @param admissionPolicyId The unique identifier of a Policy.
     * @param timestamp EVM time of the Attestation.
     * @param signature The full signature.
     * @return canIndeed True if signature is acceptable and not expired, otherwise false.
     * @return signer The verifier address recovered by ecrecover.
     */
    function canUpdateCredential(
        address user,
        bytes32 userPolicyId,
        bytes32 admissionPolicyId,
        uint256 timestamp,
        bytes calldata signature
    ) public view override returns (bool canIndeed, address signer) {
        IPolicyManager a = IPolicyManager(_policyManager);
        signer = getSignerFromSig(user, userPolicyId, admissionPolicyId, timestamp, false, signature);
        if (a.isVerifier(signer)) canIndeed = a.isPolicyVerifier(admissionPolicyId, signer);
    }

    /**********************************************************
     VIEW FUNCTIONS
     **********************************************************/

    /**
     * @return policyManager The immutable state variable _policyManager.
     */
    function getPolicyManager() external view override returns (address policyManager) {
        policyManager = _policyManager;
    }

    /**
     * @return keyringCredentials The immutable state variable _keyringCredentials.
     */
    function getKeyringCredentials() external view override returns (address keyringCredentials) {
        keyringCredentials = _keyringCredentials;
    }
}
