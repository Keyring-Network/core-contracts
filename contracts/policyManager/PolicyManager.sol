// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../interfaces/IPolicyManager.sol";
import "../interfaces/IRuleRegistry.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @notice PolicyManager holds the policies managed by DeFi Protocol Operators and users. 
 When used by a KeyringGuard, policies describe admission rules that will be enforced. 
 When used by a Trader, policies describe the rules that compliant DeFi Protocol Operators 
 must enforce in order for their contracts to be compatible with the user policy. 
 */

contract PolicyManager is IPolicyManager, KeyringAccessControl, Initializable {
    string private constant MODULE = "PolicyManager";
    address private constant NULL_ADDRESS = address(0);
    using Bytes32Set for Bytes32Set.Set;
    using AddressSet for AddressSet.Set;

    bytes32 private constant SEED_POLICY_OWNER = keccak256("policy owner role seed");
    bytes32 private constant ROLE_GLOBAL_VERIFIER_ADMIN = keccak256("global verifier admin");
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable override ruleRegistry;

    Bytes32Set.Set private policySet;
    mapping(bytes32 => Policy) private _policies;
    mapping(address => bytes32) public override userPolicy;

    AddressSet.Set private verifierSet;
    mapping(address => string) public override verifierUri;

    uint256 public override nonce;

    /**
     * @notice Policy admin role is initially granted during createPolicy.
     * @dev Revert if the msg sender doesn't have the policy admin role.
     * @param policyId The unique identifier of a Policy.
     */
    modifier onlyPolicyAdmin(bytes32 policyId) {
        _checkRole(policyId, _msgSender(), "policyManager:onlyPolicyAdmin");
        _;
    }

    /**
     * @notice Keyring Governance has exclusive access to the global whitelist of Verifiers.
     * @dev Revert if the user doesn't have the global verifier admin role.
     */
    modifier onlyVerifierAdmin() {
        _checkRole(ROLE_GLOBAL_VERIFIER_ADMIN, _msgSender(), "policyManager:onlyVerifierAdmin");
        _;
    }

    /**
     * @param trustedForwarder Contract address that is allowed to relay message signers.
     * @param ruleRegistryAddr The address of the deployed RuleRegistry contract.
     */
    constructor(address trustedForwarder, address ruleRegistryAddr)
        KeyringAccessControl(trustedForwarder)
    {
        if (trustedForwarder == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "trustedForwarder cannot be empty"
            });
        if (ruleRegistryAddr == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "ruleRegistryAddr cannot be empty"
            });
        ruleRegistry = ruleRegistryAddr;
        emit PolicyManagerDeployed(_msgSender(), trustedForwarder, ruleRegistryAddr);
    }

    /**
     * @notice This upgradeable contract must be initialized.
     * @dev Initializer function MUST be called directly after deployment.
     * because anyone can call it but overall only once.
     */
    function init() external override initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        emit PolicyManagerInitialized(_msgSender());
    }

    /**
     * @notice Anyone can create a Policy and is granted admin and user admin over the Policy.
     * @dev requiredVerifiers is never higher than the number of Verifiers in the Policy.
     * @param description The description of the Policy is not used for any logic.
     * @param ruleId The unique identifier of a rule. Each Policy has exactly one rule.
     * @param expiryTime The maximum acceptable credential age in seconds.
     * Users are forced to refresh credentials older than this interval (time in seconds).
     * @return policyId The unique identifier of a Policy.
     */
    function createPolicy(
        string calldata description,
        bytes32 ruleId,
        uint128 expiryTime
    ) public override returns (bytes32 policyId) {
        if (bytes(description).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "createPolicy",
                reason: "description cannot be empty"
            });
        if (!IRuleRegistry(ruleRegistry).isRule(ruleId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "createPolicy",
                reason: "ruleId not found"
            });
        nonce++;
        policyId = keccak256(abi.encodePacked(nonce, address(this)));
        bytes32 adminRole = keccak256(abi.encodePacked(policyId, SEED_POLICY_OWNER));
        policySet.insert(policyId, "policyManager:createPolicy: 500 Duplicate policyId");
        _grantRole(policyId, _msgSender());
        _grantRole(adminRole, _msgSender());
        _setRoleAdmin(policyId, adminRole);
        Policy storage p = _policies[policyId];
        p.description = description;
        p.ruleId = ruleId;
        p.expiryTime = expiryTime;
        emit CreatePolicy(_msgSender(), policyId, description, ruleId, 0, expiryTime, adminRole);
    }

    /**
     * @notice Anyone can create an admission Policy and is granted admin and user admin.
     * @dev `requiredVerifiers` is never higher than the number of Verifiers in the Policy.
     * @param description The description of the Policy is not used for any logic.
     * @param ruleId The unique identifier of a rule. Each Policy has exactly one rule.
     * @param expiryTime The maximum acceptable credential age in seconds.
     * @param requiredVerifiers The minimum number of signing Verifiers.
     * @param verifiers Acceptabpe verifiers
     * @return policyId The unique identifier of a Policy.
     */
    function createPolicyWithVerifiers(
        string calldata description,
        bytes32 ruleId,
        uint128 expiryTime,
        uint128 requiredVerifiers,
        address[] calldata verifiers
    ) external override returns (bytes32 policyId) {
        policyId = createPolicy(description, ruleId, expiryTime);
        addPolicyVerifiers(policyId, verifiers);
        updatePolicyRequiredVerifiers(policyId, requiredVerifiers);
    }

    /**
     * @notice The Policy admin role can update the parameters.
     * @param policyId The unique identifier of a Policy.
     * @param description The new description of the Policy.
     * @param ruleId The unique identifier of the new rule. Each Policy has exactly one rule.
     * @param requiredVerifiers The minimum number of signing Verifiers.
     * @param expiryTime The maximum acceptable credential age in seconds.
     */
    function updatePolicy(
        bytes32 policyId,
        string calldata description,
        bytes32 ruleId,
        uint128 requiredVerifiers,
        uint128 expiryTime
    ) external override onlyPolicyAdmin(policyId) {
        updatePolicyDescription(policyId, description);
        updatePolicyRuleId(policyId, ruleId);
        updatePolicyExpiryTime(policyId, expiryTime);
        updatePolicyRequiredVerifiers(policyId, requiredVerifiers);
    }

    /**
     * @notice Policy admins can update policy descriptions.
     * @param policyId The policy to update.
     * @param description The new policy description.
     */
    function updatePolicyDescription(bytes32 policyId, string memory description)
        public
        override
        onlyPolicyAdmin(policyId)
    {
        if (bytes(description).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyDescription",
                reason: "description cannot be empty"
            });
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyDescription",
                reason: "policyId not found"
            });
        Policy storage p = _policies[policyId];
        p.description = description;
        emit UpdatePolicyDescription(_msgSender(), policyId, description);
    }

    /**
     * @notice Policy admins can update policy rules.
     * @param policyId The policy to update.
     * @param ruleId The new policy rule.
     */
    function updatePolicyRuleId(bytes32 policyId, bytes32 ruleId)
        public
        override
        onlyPolicyAdmin(policyId)
    {
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyRuleId",
                reason: "policyId not found"
            });
        if (!IRuleRegistry(ruleRegistry).isRule(ruleId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyRuleId",
                reason: "ruleId not found"
            });
        Policy storage p = _policies[policyId];
        p.ruleId = ruleId;
        emit UpdatePolicyRuleId(_msgSender(), policyId, ruleId);
    }

    /**
     * @notice Policy admins can update policy required Verifiers.
     * @param policyId The policy to update.
     * @param requiredVerifiers The minimum number of signing Verifiers.
     */
    function updatePolicyRequiredVerifiers(bytes32 policyId, uint128 requiredVerifiers)
        public
        override
        onlyPolicyAdmin(policyId)
    {
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyRequiredVerifiers",
                reason: "policyId not found"
            });
        if (policyVerifierCount(policyId) < requiredVerifiers)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyRequiredVerifiers",
                reason: "add verifiers first"
            });
        Policy storage p = _policies[policyId];
        p.requiredVerifiers = requiredVerifiers;
        emit UpdatePolicyRequiredVerifiers(_msgSender(), policyId, requiredVerifiers);
    }

    /**
     * @notice Policy admins can update policy credential expiry times.
     * @param policyId The policy to update.
     * @param expiryTime The maximum acceptable credential age in seconds.
     */
    function updatePolicyExpiryTime(bytes32 policyId, uint128 expiryTime)
        public
        override
        onlyPolicyAdmin(policyId)
    {
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updatePolicyExpiryTime",
                reason: "policyId not found"
            });
        Policy storage p = _policies[policyId];
        p.expiryTime = expiryTime;
        emit UpdatePolicyExpiryTime(_msgSender(), policyId, expiryTime);
    }

    /**
     * @notice The Policy admin selects whitelisted Verifiers that are acceptable for their Policy.
     * @param policyId The policy to update.
     * @param verifiers The address of one or more Verifiers to add to the Policy.
     */
    function addPolicyVerifiers(bytes32 policyId, address[] calldata verifiers)
        public
        override
        onlyPolicyAdmin(policyId)
    {
        for (uint256 i = 0; i < verifiers.length; i++) {
            _addPolicyVerifier(policyId, verifiers[i]);
        }
    }

    /**
     * @notice The Policy admin selects whitelisted Verifiers that are acceptable for their Policy.
     * @param policyId The policy to update.
     * @param verifiers The address of one or more Verifiers to remove from the Policy.
     */
    function removePolicyVerifiers(bytes32 policyId, address[] calldata verifiers)
        public
        override
        onlyPolicyAdmin(policyId)
    {
        for (uint256 i = 0; i < verifiers.length; i++) {
            _removePolicyVerifier(policyId, verifiers[i]);
        }
    }    

    /**
     * @notice Each user sets exactly one Policy to check when trading.
     * @param policyId The unique identifier of a Policy.
     */
    function setUserPolicy(bytes32 policyId) external override {
        address sender = _msgSender();
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: sender,
                module: MODULE,
                method: "setUserPolicy",
                reason: "policyId not found"
            });
        userPolicy[sender] = policyId;
        emit SetUserPolicy(sender, policyId);
    }

    /**
     * @notice The Global Verifier Admin can admit Verifiers to the global whitelist.
     * @param verifier The address of a Verifier to admit into the global whitelist.
     * @param uri The URI points to detailed information about the verifier.
     */
    function admitVerifier(address verifier, string calldata uri)
        external
        override
        onlyVerifierAdmin
    {
        if (verifier == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "admitVerifier",
                reason: "verifier address cannot be empty"
            });
        if (bytes(uri).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "admitVerifier",
                reason: "verifier uri cannot be empty"
            });
        verifierSet.insert(verifier, "policymanager:admitVerifier: already admitted");
        verifierUri[verifier] = uri;
        emit AdmitVerifier(_msgSender(), verifier, uri);
    }

    /**
     * @notice The Global Verifier Admin can update the uris for Verifiers on the global whitelist.
     * @param verifier The address of a Verifier in the global whitelist.
     * @param uri The new uri for the Verifier.
     */
    function updateVerifierUri(address verifier, string calldata uri)
        external
        override
        onlyVerifierAdmin
    {
        if (bytes(uri).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateVerifierUri",
                reason: "verifier uri cannot be empty"
            });
        if (!verifierSet.exists(verifier))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateVerifierUri",
                reason: "verifier not found"
            });
        verifierUri[verifier] = uri;
        emit UpdateVerifierUri(_msgSender(), verifier, uri);
    }

    /**
     * @notice The Global Verifier Admin can remove Verifiers from the global whitelist.
     * @dev Does not automatically remove Verifiers from affected Policies.
     * @param verifier The address of a Verifier on the global whitelist.
     */
    function removeVerifier(address verifier) external override onlyVerifierAdmin {
        verifierSet.remove(verifier, "policymanager:removeVerifier: not a policy verifier.");
        emit RemoveVerifier(_msgSender(), verifier);
    }

    /**
     * @notice The Policy admin selects whitelisted Verifiers that are acceptable for their Policy.
     * @param policyId The policy to update.
     * @param verifier The address of a Verifier to accept.
     */
    function _addPolicyVerifier(bytes32 policyId, address verifier)
        internal
    {
        if (!isVerifier(verifier))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "addPolicyVerifier",
                reason: "verifier not found in the global list"
            });
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "addPolicyVerifier",
                reason: "policyId not found"
            });
        Policy storage p = _policies[policyId];
        p.verifierSet.insert(verifier, "policyManager:addPolicyVerifier: already added");
        emit AddPolicyVerifier(_msgSender(), policyId, verifier);
    }


    /**
     * @notice The Policy admin can remove Verifiers from the list of acceptable Verifiers for the Policy.
     * @param policyId The policy to update.
     * @param verifier The address of a Verifier to remove.
     */
    function _removePolicyVerifier(bytes32 policyId, address verifier)
        internal
    {
        if (!isPolicy(policyId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "removePolicyVerifier",
                reason: "policyId not found"
            });
        Policy storage p = _policies[policyId];
        if (policyVerifierCount(policyId) <= p.requiredVerifiers)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "removePolicyVerifier",
                reason: "lower requiredVerifiers first"
            });
        p.verifierSet.remove(verifier, "policymanager:removePolicyVerifier");
        emit RemovePolicyVerifier(_msgSender(), policyId, verifier);
    }

    /**********************************************************
     VIEW FUNCTIONS
     **********************************************************/

    /**
     * @param policyId The unique identifier of a Policy.
     * @dev Does not check existance. 
     * @return ruleId Enforced Rule from RuleRegistry.
     * @return description The policy description.
     * @return requiredVerifiers Minimum verifier signatures needed to update a Credential.
     * @return expiryTime The maximum age of acceptable credentials, in seconds.
     * @return verifierSetCount The number of verifiers added to the Policy.
     */
    function policy(bytes32 policyId)
        external
        view
        override
        returns (
            bytes32 ruleId,
            string memory description,
            uint128 requiredVerifiers,
            uint128 expiryTime,
            uint256 verifierSetCount
        )
    {
        Policy storage p = _policies[policyId];
        return (p.ruleId, p.description, p.requiredVerifiers, p.expiryTime, p.verifierSet.count());
    }

    /**
     * @param policyId The unique identifier of a Policy.
     * @dev Does not check existance.
     * @return ruleId Enforced Rule from RuleRegistry.
     */
    function policyRuleId(bytes32 policyId) external view override returns (bytes32 ruleId) {
        ruleId = _policies[policyId].ruleId;
    }

    /**
     * @param policyId The unique identifier of a Policy.
     * @dev Does not check existance.
     * @return description Not used for any on-chain logic.
     */
    function policyDescription(bytes32 policyId)
        external
        view
        override
        returns (string memory description)
    {
        description = _policies[policyId].description;
    }

    /**
     * @param policyId The unique identifier of a Policy.
     * @dev Does not check existance.     
     * @return minimum The number of Verifier signatures needed to update a Credential.
     */
    function policyRequiredVerifiers(bytes32 policyId)
        external
        view
        override
        returns (uint128 minimum)
    {
        minimum = _policies[policyId].requiredVerifiers;
    }

    /**
     * @param policyId The unique identifier of a Policy.
     * @dev Does not check existance.
     * @return expiryTime The maximum age of acceptable credentials.
     */
    function policyExpiryTime(bytes32 policyId) external view override returns (uint128 expiryTime) {
        expiryTime = _policies[policyId].expiryTime;
    }

    /**
     * @param policyId The policy to inspect.
     * @dev Does not check existance.
     * @return count The count of acceptable Verifiers for the Policy.
     */
    function policyVerifierCount(bytes32 policyId) public view override returns (uint256 count) {
        count = _policies[policyId].verifierSet.count();
    }

    /**
     * @param policyId The Policy to inspect.
     * @dev Does not check Policy existance.
     * @param index The list index to inspect.
     * @return verifier The address of a Verifier that is acceptable for the Policy.
     */
    function policyVerifierAtIndex(bytes32 policyId, uint256 index)
        external
        view
        override
        returns (address verifier)
    {
        Policy storage p = _policies[policyId];
        if (index >= p.verifierSet.count())
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "policyVerifierAtIndex",
                reason: "index out of range"
            });
        verifier = p.verifierSet.keyAtIndex(index);
    }

    /**
     * @param policyId The Policy to inspect.
     * @param verifier The address to inspect.
     * @dev Does not check Policy existance.
     * @return isIndeed True if verifier is acceptable for the Policy, otherwise false.
     */
    function isPolicyVerifier(bytes32 policyId, address verifier)
        external
        view
        override
        returns (bool isIndeed)
    {
        isIndeed = _policies[policyId].verifierSet.exists(verifier);
    }    

    /**
     * @dev Does not check existance.
     * @return count Existing policies in PolicyManager.
     */
    function policyCount() public view override returns (uint256 count) {
        count = policySet.count();
    }

    /**
     * @param index The list index to inspect.
     * @return policyId The unique identifier of a Policy.
     */
    function policyAtIndex(uint256 index) external view override returns (bytes32 policyId) {
        if (index >= policyCount())
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "policyAtIndex",
                reason: "index out of range"
            });
        policyId = policySet.keyAtIndex(index);
    }

    /**
     * @param policyId The unique identifier of a Policy.
     * @return isIndeed True if Policy with policyId exists, otherwise false.
     */
    function isPolicy(bytes32 policyId) public view override returns (bool isIndeed) {
        isIndeed = policySet.exists(policyId);
    }

    /**
     * @return count Total count of Verifiers admitted to the global whitelist.
     */
    function verifierCount() external view override returns (uint256 count) {
        count = verifierSet.count();
    }

    /**
     * @param index The list index to inspect.
     * @return verifier A Verifier address from the global whitelist.
     */
    function verifierAtIndex(uint256 index) external view override returns (address verifier) {
        if (index >= verifierSet.count())
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "verifierAtIndex",
                reason: "index out of range"
            });
        verifier = verifierSet.keyAtIndex(index);
    }

    /**
     * @param verifier An address
     * @return isIndeed True if the verifier is admitted to the global whitelist.
     */
    function isVerifier(address verifier) public view override returns (bool isIndeed) {
        isIndeed = verifierSet.exists(verifier);
    }

    /**
     * @return seed The constant SEED_POLICY_OWNER.
     */
    function policyOwnerSeed() external pure override returns (bytes32 seed) {
        seed = SEED_POLICY_OWNER;
    }

    /**
     * @return role  The constant ROLE_GLOBAL_VERIFIER_ADMIN.
     */
    function roleGlobalVerifierAdmin() external pure override returns (bytes32 role) {
        role = ROLE_GLOBAL_VERIFIER_ADMIN;
    }
}
