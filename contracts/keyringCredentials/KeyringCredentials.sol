// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IKeyringCredentials.sol";
import "../interfaces/IPolicyManager.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 @notice Holds the time-limited credential cache, organized by user and admission policy. 
 The credentials are non-transferrable and are represented as timestamps. Non-zero 
 entries indicate that an authorized credential updater such as the KeyringZkCredentialUpdater
 accepted evidence of compliance and recorded it here with a timestamp to indicate the 
 start time to use for calculating the credential's age. 
 */

contract KeyringCredentials is IKeyringCredentials, KeyringAccessControl, Initializable {

    address private constant NULL_ADDRESS = address(0);
    uint8 private constant VERSION = 1;
    bytes32 public constant ROLE_CREDENTIAL_UPDATER = keccak256("Credentials updater");
    address public immutable policyManager;

    /**
     @dev Epochs enable immediate and O(1) destruction of all cached credentials for a single policy. This
     is a contingency function for extraordinary circumstances. For example, ejecting especially troublesome
     users with cached credentials with immediate effect by forcing everyone to attempt to gather new
     attestations and refresh their cached credentials if they want to interact with the subject policy.
     */
    mapping(uint32 => uint256) public policyEpochs;

    /**
     @dev The credentials are indexed by (version => trader => admissionPolicyId => epoch) => updateTime
     where the version is always 1 and the epoch supports emergency tear-down of all cached credentials
     for a given policy, if the policy owner orders it. 
     */
    mapping(uint8 => mapping(address => mapping(uint32 => mapping(uint256 => uint256))))
        public override cache;

    /**
     @notice Revert if the message sender doesn't have the Credentials updater role.
     */
    modifier onlyUpdater() {
        _checkRole(ROLE_CREDENTIAL_UPDATER, _msgSender(), "KeyringCredentials:onlyUpdater");
        _;
    }

    /**
     * @notice Only the PolicyAdmin can tear down user credentials.
     */
    modifier onlyPolicyAdmin(uint32 policyId) {
        // IPolicyManager(policyManager).policyOwnerRole(policyId);
        bytes32 ownerRole = bytes32(uint256(policyId));
        if(!IPolicyManager(policyManager).hasRole(ownerRole, _msgSender())) {
           revert Unacceptable({
                reason: "unauthorized"
            }); 
        }
        _;
    }

    /**
     @param trustedForwarder Contract address that is allowed to relay message signers.
     */
    constructor(address trustedForwarder, address policyManager_) KeyringAccessControl(trustedForwarder) {
        if (trustedForwarder == NULL_ADDRESS)
            revert Unacceptable({
                reason: "trustedForwarder cannot be empty"
            });
        if (policyManager_ == NULL_ADDRESS)
            revert Unacceptable({
                reason: "policyManager_ cannot be empty"
            });
        policyManager = policyManager_;
        emit CredentialsDeployed(_msgSender(), trustedForwarder, policyManager);
    }

    /**
     @notice This upgradeable contract must be initialized.
     @dev The initializer function MUST be called directly after deployment 
     because anyone can call it but overall only once.
     */
    function init() external override initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        emit CredentialsInitialized(_msgSender());
    }

    /**
     * @notice The policy admin can invalidate all stored credentials for a given policy. 
     * @param policyId The policy with credentials to tear down
     */
    function tearDownAdmissionPolicyCredentials(uint32 policyId) external override onlyPolicyAdmin(policyId) {
        policyEpochs[policyId]++;
        emit TearDownAdmissionPolicyCredentials(_msgSender(), policyId);
    }

    /**
     * @notice An updater can tear down all stored credentials for a given policy. 
     * @param policyId The policy with credentials to tear down
     */
    function resetPolicyCredentials(uint32 policyId) external override onlyUpdater {
        policyEpochs[policyId]++;
        emit TearDownAdmissionPolicyCredentials(_msgSender(), policyId);
    }

    /**
     @notice This function is called by a trusted and permitted contract such as the 
     KeyringZkCredentialUpdater. There is no prohibition on multiple proving schemes 
     at the cache level since this contract requires only that the caller has permission.
     @param trader The user address for the Credential update.
     @param admissionPolicyId The unique identifier of a Policy.
     @param timestamp The timestamp established by the credential updater.
     */
    function setCredential(
        address trader,
        uint32 admissionPolicyId,
        uint256 timestamp
    ) external override onlyUpdater {
        if (timestamp > block.timestamp)
            revert Unacceptable({
                reason: "timestamp must be in the past"
            });
        uint256 admissionPolicyEpoch = policyEpochs[admissionPolicyId];
        if (cache[VERSION][trader][admissionPolicyId][admissionPolicyEpoch] > timestamp)
            revert Unacceptable({
                reason: "timestamp is older than existing credential"
            });
        cache[VERSION][trader][admissionPolicyId][admissionPolicyEpoch] = timestamp;
        emit UpdateCredential(1, _msgSender(), trader, admissionPolicyId, admissionPolicyEpoch);
    }

    /**
     @notice Inspect the credential cache.
     @param version Cache organization version.
     @param trader The user to inspect.
     @param admissionPolicyId The admission policy for the credential to inspect.
     @return timestamp The timestamp established when the credential was recorded. 0 if no credential.
     */
    function getCredential(
        uint8 version, 
        address trader, 
        uint32 admissionPolicyId
    ) external view returns (uint256 timestamp) {
        uint256 admissionPolicyEpoch = policyEpochs[admissionPolicyId];
        timestamp = cache[version][trader][admissionPolicyId][admissionPolicyEpoch];
    }
}
