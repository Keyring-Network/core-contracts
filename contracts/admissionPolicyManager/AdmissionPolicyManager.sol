// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

import "../interfaces/IAdmissionPolicyManager.sol";
import "../interfaces/IPolicyManager.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract AdmissionPolicyManager is IAdmissionPolicyManager, KeyringAccessControl, Initializable {

    using Bytes32Set for Bytes32Set.Set;
    using AddressSet for AddressSet.Set;

    bytes32 public constant ROLE_ADMISSION_POLICY_MANAGER = keccak256("role admission policy manager");
    bytes32 public constant ROLE_KYC_ADMIN = keccak256("role kyc admin");
    address public immutable policyManager;

    Bytes32Set.Set admissionPolicySet;
    mapping(bytes32 => AdmissionPolicy) private _admissionPolicies;

    AddressSet.Set kycSignerSet;

    uint256 public nonce;

    bool[50] private _reservedSlots;

    modifier onlyAdmissionPolicyAdmin(bytes32 admissionPolicyId) {
        _checkRole(
            admissionPolicyId,
            _msgSender(),
            "AdmissionPolicyManager:onlyPolicyAdmin");
        _;
    }

    modifier onlyKycAdmin {
        _checkRole(
            ROLE_KYC_ADMIN,
            _msgSender(),
            "AdmissionPolicyManager:onlyKycAdmin");
        _;
    }

    constructor(address trustedForwarder, address policyManager_) KeyringAccessControl(trustedForwarder) {
        policyManager = policyManager_;
        emit Deployed(_msgSender(), trustedForwarder, policyManager_);
    }

    function init() external initializer {
        _setupRole(
            DEFAULT_ADMIN_ROLE,
            _msgSender());
    }

    /**********************************************************
     Anyone can create an admission policy and is granted two roles:
        1. admin role of the same id as the admissionPolicy
        2. user admin role for the new admission policy
     **********************************************************/

    function createAdmissionPolicy(bytes32 policyId, uint256 quorum, uint256 secondsToLive) external returns(bytes32 admissionPolicyId) {
        require(
            IPolicyManager(policyManager).isPolicy(policyId),
            "AdmissionPolicyManager:createAdmissionPolicy: policyId not found");
        nonce++;
        admissionPolicyId = keccak256(abi.encodePacked(nonce, address(this)));
        bytes32 adminPolicy = admissionPolicyUserAdminRole(admissionPolicyId);
        _setupRole(
            admissionPolicyId,
            _msgSender());
        _setupRole(
            adminPolicy,
            _msgSender());
        _setRoleAdmin(
            admissionPolicyId, 
            adminPolicy);
        AdmissionPolicy storage a = _admissionPolicies[admissionPolicyId];
        a.policyId = policyId;
        a.quorum = quorum;
        a.secondsToLive = secondsToLive;
        emit CreateAdmissionPolicy(_msgSender(), admissionPolicyId, policyId, quorum, secondsToLive, adminPolicy);
    }

    function updateAdmissionPolicy(bytes32 admissionPolicyId,bytes32 policyId, uint256 quorum, uint256 secondsToLive) 
        external 
        onlyAdmissionPolicyAdmin(admissionPolicyId) 
    {
        require(
            isAdmissionPolicy(admissionPolicyId),
            "AdmissionPolicyManager:updateAdmissionPolicy");
        require(
            IPolicyManager(policyManager).isPolicy(policyId),
            "AdmissionPolicyManager:createAdmissionPolicy: policyId not found"); // todo, redundant? 
        AdmissionPolicy storage a = _admissionPolicies[admissionPolicyId];
        a.policyId = policyId;
        a.quorum = quorum;
        a.secondsToLive = secondsToLive;
        emit UpdateAdmissionPolicy(_msgSender(), admissionPolicyId, policyId, secondsToLive, quorum);      
    }

    function removeAdmissionPolicy(bytes32 admissionPolicyId) external onlyAdmissionPolicyAdmin(admissionPolicyId) {
        admissionPolicySet.remove(
            admissionPolicyId,
            "AdmissionPolicyManager:removeAdmissionPolicy");
        delete _admissionPolicies[admissionPolicyId];
        emit RemoveAdmissionPolicy(_msgSender(), admissionPolicyId);
    }

    function addAdmissionPolicyKycSigner(bytes32 admissionPolicyId, address kycSigner) external onlyAdmissionPolicyAdmin(admissionPolicyId) {
        require(
            isKycSigner(kycSigner),
            "AdmissionPolicyManager:addAdmissionPolicyKycSigner: kycSigner not in the admission policy");
        require(
            isAdmissionPolicy(admissionPolicyId),
            "AdmissionPolicy:addAdmissionPolicyKycSigner: admissionPolicyId not found"); // todo redundant?
        AdmissionPolicy storage a = _admissionPolicies[admissionPolicyId];
        a.kycSignerSet.insert(
            kycSigner,
            "AdmissionPolicy:addAdmissionPolicyKycSigner");
        emit AddAdmissionPolicyKycSigner(_msgSender(), admissionPolicyId, kycSigner);
    }

    function removeAdmissionPolicyKycSigner(bytes32 admissionPolicyId, address kycSigner) external onlyAdmissionPolicyAdmin(admissionPolicyId) {
        require(
            isKycSigner(kycSigner),
            "AdmissionPolicyManager:removeAdmissionPolicyKycSigner: kycSigner not in the admission policy");
        require(
            isAdmissionPolicy(admissionPolicyId),
            "AdmissionPolicy:removeAdmissionPolicyKycSigner: admissionPolicyId not found"); // todo redundant?
        AdmissionPolicy storage a = _admissionPolicies[admissionPolicyId];
        require(
            a.kycSignerSet.count() > a.quorum,
            "AdmissionPolicyManager:removeAdmissionPolicyKycSigner: Cannot remove. Must have enough signers to achieve quorum");
        a.kycSignerSet.remove(
            kycSigner,
            "AdmissionPolicy:removeAdmissionPolicyKycSigner");
        emit RemoveAdmissionPolicyKycSigner(_msgSender(), admissionPolicyId, kycSigner);        
    }

    /**********************************************************
     Keyring admits KYC signers.
     **********************************************************/

    function admitKycSigner(address kycSigner) external onlyKycAdmin {
        kycSignerSet.insert(
            kycSigner,
            "AdmissionPolicyManager:createKycSigner");
        emit AdmitKycSigner(_msgSender(), kycSigner);
    }

    function removeKycSigner(address kycSigner) external onlyKycAdmin {
        kycSignerSet.remove(
            kycSigner,
            "AdmissionPolicyManager:removeKycSigner");
        emit RemoveKycSigner(_msgSender(), kycSigner);
    }
    
    /**********************************************************
     VIEW FUNCTIONS
     **********************************************************/
    
    function admissionPolicy(bytes32 admissionPolicyId) external view returns(bytes32 policyId, uint256 quorum, uint256 secondsToLive, uint256 keySignerCount) {
        AdmissionPolicy storage a = _admissionPolicies[admissionPolicyId];
        return(a.policyId, a.quorum, a.secondsToLive, a.kycSignerSet.count());
    }

    function getTimeToLive(bytes32 admissionPolicyId) external view returns(uint256 secondsToLive) {
        secondsToLive = _admissionPolicies[admissionPolicyId].secondsToLive;
    }

    function getQuorum(bytes32 admissionPolicyId) external view returns(uint256 minimum) {
        minimum = _admissionPolicies[admissionPolicyId].quorum;
    }

    function admissionPolicyCount() public view returns(uint256 count) {
        count = admissionPolicySet.count();
    }

    function admissionPolicyAtIndex(uint256 index) external view returns(bytes32 admissionPolicyId) {
        require(
            index < admissionPolicyCount(),
            "AdmissionPolicyManager:admissionPolicyAtIndex");
        admissionPolicyId = admissionPolicySet.keyAtIndex(index);
    }

    function isAdmissionPolicy(bytes32 admissionPolicyId) public view returns(bool isIndeed) {
        isIndeed = admissionPolicySet.exists(admissionPolicyId);
    }

    function admissionPolicyUserAdminRole(bytes32 admissionPolicyId) public pure returns(bytes32 role) {
        role = keccak256(abi.encodePacked(ROLE_ADMISSION_POLICY_MANAGER, admissionPolicyId));
    }

    function kycSignerCount() external view returns(uint256 count) {
        count = kycSignerSet.count();
    }

    function kycSignerAtIndex(uint256 index) external view returns(address kycSigner) {
        kycSigner = kycSignerSet.keyAtIndex(index);
    }

    function isKycSigner(address kycSigner) public view returns(bool isIndeed) {
        isIndeed = kycSignerSet.exists(kycSigner);
    }

    function admissionPolicyKycSignerAtIndex(bytes32 admissionPolicyId, uint256 index) external view returns(address kycSigner) {
        return _admissionPolicies[admissionPolicyId].kycSignerSet.keyAtIndex(index);
    }

    function isAdmissionPolicyKycSigner(bytes32 admissionPolicyId, address kycSigner) external view returns(bool isIndeed) {
        isIndeed = _admissionPolicies[admissionPolicyId].kycSignerSet.exists(kycSigner);
    }

}
