// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

import "../interfaces/IKeyringSignatureVerifier.sol";
import "../access/KeyringAccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract KeyringSignatureVerifier is IKeyringSignatureVerifier, KeyringAccessControl, EIP712 {

    bytes32 public constant ROLE_GRACE_ADMIN = keccak256("role admin");
    uint256 public graceTime = 10 * 1 minutes;

    modifier onlyGraceAdmin {
        _checkRole(
            ROLE_GRACE_ADMIN,
            _msgSender(),
            "KeyringSignatureVerifier:onlyGraceAdmin");
        _;
    }

    constructor(address trustedForwarder) 
        KeyringAccessControl(trustedForwarder)
        EIP712("Keyring", "0.1") 
    {
        _setupRole(
            DEFAULT_ADMIN_ROLE,
            _msgSender());
        emit Deployed(_msgSender(), trustedForwarder);
    }

    function setGraceTime(uint256 timeSeconds) external onlyGraceAdmin {
        require(
            timeSeconds > 0,
            "KeyringSignatureVerifier:setGraceTime: timeSeconds cannot be 0");
        graceTime = timeSeconds * 1 seconds;
        emit SetGraceTime(_msgSender(), timeSeconds);
    }

    /*******************************************************************
     return the attestation signer address
     *******************************************************************/

    function attestationSigner(bytes32 policyId, address userId, uint256 timestamp, bytes memory signature) 
        internal 
        view 
        returns(address signer) 
    {
        bytes32 digest = _attestationDigest(policyId, userId, timestamp);
        bytes32 hash = _attestationHash(digest);
        uint256 age = block.timestamp - timestamp;
        if(age <= graceTime) signer = _messageSigner(hash, signature);
    }

    /*******************************************************************
     private functions
     *******************************************************************/

    function _attestationDigest(bytes32 policyId, address userId, uint256 timestamp) private view returns(bytes32 digest) {
        digest = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("Attestation(bytes32 policyId,address userId,uint256 timestamp)"),
            policyId,
            userId,
            timestamp
        )));
    }

    function _attestationHash(bytes32 digest) private view returns(bytes32 hash) {
        hash = keccak256(abi.encodePacked('\x19\x01', _domainSeparatorV4(), digest));
    }

    function _messageSigner(bytes32 hash, bytes memory signature) private pure returns(address signer) {
        signer = ECDSA.recover(hash, signature);
    }

}