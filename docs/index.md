# Solidity API

## KeyringAccessControl

This contract manages the role-based access control via _checkRole() with meaningful 
 error messages if the user does not have the requested role. This contract is inherited by 
 PolicyManager, RuleRegistry, KeyringCredentials, IdentityTree, WalletCheck and 
 KeyringZkCredentialUpdater.

### Unauthorized

```solidity
error Unauthorized(address sender, string module, string method, bytes32 role, string reason, string context)
```

### constructor

```solidity
constructor(address trustedForwarder) internal
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |

### _checkRole

```solidity
function _checkRole(bytes32 role, address account, string context) internal view
```

Role-based access control.

_Reverts if the account is missing the role._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| role | bytes32 | The role to check. |
| account | address | An address to check for the role. |
| context | string | For reporting purposes. Usually the function that requested the permission check. |

### _msgSender

```solidity
function _msgSender() internal view virtual returns (address sender)
```

Returns ERC2771 signer if msg.sender is a trusted forwarder, otherwise returns msg.sender.

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| sender | address | User deemed to have signed the transaction. |

### _msgData

```solidity
function _msgData() internal view virtual returns (bytes)
```

Returns msg.data if not from a trusted forwarder, or truncated msg.data if the signer was 
     appended to msg.data

_Although not currently used, this function forms part of ERC2771 so is included for completeness._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bytes | data Data deemed to be the msg.data |

## KeyringZkCredentialUpdater

This contract acts as a credentials cache updater. It needs the ROLE_CREDENTIAL_UPDATER 
 permission in the KeyringCredentials contract in order to record credentials. The contract checks 
 client-generated zero-knowledge proofs of attestations about admission policy eligibility and 
 therefore enforces the protocol.

### ROLE_IDENTITY_TREE_ADMIN

```solidity
bytes32 ROLE_IDENTITY_TREE_ADMIN
```

### POLICY_MANAGER

```solidity
address POLICY_MANAGER
```

### KEYRING_CREDENTIALS

```solidity
address KEYRING_CREDENTIALS
```

### KEYRING_ZK_VERIFIER

```solidity
address KEYRING_ZK_VERIFIER
```

### constructor

```solidity
constructor(address trustedForwarder, address keyringCredentials, address policyManager, address keyringZkVerifier) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| keyringCredentials | address | The address for the deployed KeyringCredentials contract to write to. |
| policyManager | address | The address for the deployed PolicyManager contract to read from. |
| keyringZkVerifier | address | On-chain instance of the stateless Keyring ZK verifier contract. |

### updateCredentials

```solidity
function updateCredentials(address attestor, struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorizationProof) external
```

Updates the credential cache if the request is acceptable.

_The attestor must be valid for all policy disclosures. For this to be possible, it must have been admitted
     to the system globally before it was selected for a policy. The two zero-knowledge proof share parameters that ensure
     that both proofs were derived from the same identity commitment._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | The identityTree contract with a root that contains the user's identity commitment. Must be present      in the current attestor list for all policy disclosures in the authorization proof. |
| membershipProof | struct IKeyringZkVerifier.IdentityMembershipProof | A zero-knowledge proof of identity commitment membership in the identity tree. Contains an      external nullifier and nullifier hash that must match the parameters of the authorization proof. |
| authorizationProof | struct IKeyringZkVerifier.IdentityAuthorisationProof | A zero-knowledge proof of compliance with up to 24 policy disclosures. Contains an      external nullifier and nullifier hash that must match the parameters of the membershiip proof. |

### checkPolicyAndWallet

```solidity
function checkPolicyAndWallet(address trader, uint32 policyId, address attestor) public returns (bool acceptable)
```

The identity tree must be a policy attestor, the wallet must not be flagged by any policy wallet
check and the policy rule cannot be toxic.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The trader wallet to inspect. |
| policyId | uint32 | The policy to inspect. |
| attestor | address | The identity tree contract address to compare to the policy attestors. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| acceptable | bool | True if the policy rule is not toxic, the identity tree is authoritative for the poliy       and the wallet is not flagged in any wallet check contract that is authoritative for the policy. |

### pack12x20

```solidity
function pack12x20(uint32[12] input) public pure returns (uint256 packed)
```

Packs uint32[12] into uint256 with 20-bit precision.

_This function will disregard bits greater than 20 bits of magnitude._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| input | uint32[12] | 20 bit unsigned integers cast as uint32. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| packed | uint256 | Uint256 packed format contained encoding of 12 20-bit uints. |

### unpack12x20

```solidity
function unpack12x20(uint256 packed) public pure returns (uint32[12] unpacked)
```

Unpacks packed elements as 20-bit uint32[12].

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| packed | uint256 | Packed format, 12 x 20-bit unsigned integers, tightly packed. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| unpacked | uint32[12] | Uint32[12], 20-bit precision. |

## IdentityTree

This contract holds the history of identity tree merkle roots announced by the aggregator. 
 Each root has an associated birthday that records when it was created. Zero-knowledge proofs rely
 on these roots. Claims supported by proofs are considered to be of the same age as the roots they
 rely on for validity.

### ROLE_AGGREGATOR

```solidity
bytes32 ROLE_AGGREGATOR
```

### MAX_SUCCESSORS

```solidity
uint256 MAX_SUCCESSORS
```

### merkleRootBirthday

```solidity
mapping(bytes32 => uint256) merkleRootBirthday
```

### merkleRootSet

```solidity
struct Bytes32Set.Set merkleRootSet
```

### onlyAggregator

```solidity
modifier onlyAggregator()
```

### constructor

```solidity
constructor(address trustedForwarder) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |

### setMerkleRootBirthday

```solidity
function setMerkleRootBirthday(bytes32 merkleRoot, uint256 birthday) external
```

The aggregator can set roots with non-zero birthdays.

_Explicit birthday declaration ensures that root age is not extended by mining delays._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| merkleRoot | bytes32 | The merkleRoot to set. |
| birthday | uint256 | The timestamp of the merkleRoot. 0 to invalidate the root. |

### merkleRootCount

```solidity
function merkleRootCount() public view returns (uint256 count)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The number of merkle roots recorded since the beginning |

### merkleRootAtIndex

```solidity
function merkleRootAtIndex(uint256 index) external view returns (bytes32 merkleRoot)
```

Enumerate the recorded merkle roots.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | Row to return. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| merkleRoot | bytes32 | The root stored at the row. |

### isMerkleRoot

```solidity
function isMerkleRoot(bytes32 merkleRoot) external view returns (bool isIndeed)
```

Check for existence in history.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| merkleRoot | bytes32 | The root to check. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the root has been recorded. |

### merkleRootSuccessors

```solidity
function merkleRootSuccessors(bytes32 merkleRoot) external view returns (uint256 successors)
```

Returns the count of roots recorded after the root to inspect.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| merkleRoot | bytes32 | The root to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| successors | uint256 | The count of roots recorded after the root to inspect. |

## KeyringGuard

Provides the core support for functions and modifiers that inspect trader compliance
 with admission policies using the credential cache.

### Compliance

```solidity
error Compliance(address sender, address user, string module, string method, string reason)
```

### _isCompliant

```solidity
function _isCompliant(address user, address keyringCredentials, address policyManager, uint32 admissionPolicyId, bytes32 universeRule, bytes32 emptyRule) internal returns (bool isIndeed)
```

Checks if the given user has a stored, fresh credential for the admission policy in the
     credential cache.

_Use static call to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The user address, normally a trading wallet, to check. |
| keyringCredentials | address | The address for the deployed KeyringCredentials contract. |
| policyManager | address | The address of the deployed PolicyManager contract to rely on. |
| admissionPolicyId | uint32 | The unique identifier of a Policy. |
| universeRule | bytes32 | The id of the universe (everyone) Rule. |
| emptyRule | bytes32 | The id of the empty (noone) Rule. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if a valid credential is found and its age is less than or equal to      the admission policy's TTL. |

## KeyringGuardImmutable

KeyringGuard implementation that uses immutable configuration parameters and presents 
 a simplified modifier for use in derived contracts.

### NULL_ADDRESS

```solidity
address NULL_ADDRESS
```

### NULL_BYTES32

```solidity
bytes32 NULL_BYTES32
```

### keyringCompliance

```solidity
modifier keyringCompliance(address user)
```

_Use this modifier in derived contracts to enforce user compliance with the admission policy._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | User address to check. |

### constructor

```solidity
constructor(address keyringCredentials, address policyManager, uint32 admissionPolicyId) internal
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| keyringCredentials | address | The KeyringCredentials contract to rely on. |
| policyManager | address | The address of the deployed PolicyManager to rely on. |
| admissionPolicyId | uint32 | The unique identifier of a Policy against which user accounts will be compared. |

### getKeyringCredentials

```solidity
function getKeyringCredentials() external view returns (address keyringCredentials)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| keyringCredentials | address | The KeyringCredentials contract to rely on. |

### getKeyringPolicyManager

```solidity
function getKeyringPolicyManager() external view returns (address policyManager)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyManager | address | The PolicyManager contract to rely on. |

### getKeyringAdmissionPolicyId

```solidity
function getKeyringAdmissionPolicyId() external view returns (uint32 admissionPolicyId)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| admissionPolicyId | uint32 | The unique identifier of the admission Policy. |

### getKeyringGenesisRules

```solidity
function getKeyringGenesisRules() external view returns (bytes32 universeRuleId, bytes32 emptyRuleId)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| universeRuleId | bytes32 | The id of the universal set Rule (everyone), |
| emptyRuleId | bytes32 | The id of the null set Rule (no one), |

### checkKeyringCompliance

```solidity
function checkKeyringCompliance(address user) external returns (bool isCompliant)
```

Checks user compliance status.

_Use static call to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | User to check. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isCompliant | bool | True if the user would be permitted to proceed. |

### _isPolicy

```solidity
function _isPolicy(address policyManager, uint32 policyId) internal view returns (bool isIndeed)
```

Checks the existence of a policy in the PolicyManager contract.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyManager | address | The address of the deployed PolicyManager contract to query. |
| policyId | uint32 | The unique identifier of a policy. |

## IAuthorizationProofVerifier

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[5] input) external view returns (bool)
```

## IIdentityConstructionProofVerifier

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] input) external view returns (bool r)
```

## IIdentityMembershipProofVerifier

_Interface of Verifier contract._

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[4] input) external view
```

## IIdentityTree

### MerkleRoot

```solidity
struct MerkleRoot {
  bytes32 root;
  uint256 birthday;
}
```

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### SetMerkleRootBirthday

```solidity
event SetMerkleRootBirthday(bytes32 merkleRoot, uint256 birthday)
```

### ROLE_AGGREGATOR

```solidity
function ROLE_AGGREGATOR() external view returns (bytes32)
```

### MAX_SUCCESSORS

```solidity
function MAX_SUCCESSORS() external view returns (uint256)
```

### merkleRootBirthday

```solidity
function merkleRootBirthday(bytes32 root) external view returns (uint256)
```

### setMerkleRootBirthday

```solidity
function setMerkleRootBirthday(bytes32 root, uint256 birthday) external
```

### merkleRootCount

```solidity
function merkleRootCount() external view returns (uint256 count)
```

### merkleRootAtIndex

```solidity
function merkleRootAtIndex(uint256 index) external view returns (bytes32 merkleRoot)
```

### isMerkleRoot

```solidity
function isMerkleRoot(bytes32 merkleRoot) external view returns (bool isIndeed)
```

### merkleRootSuccessors

```solidity
function merkleRootSuccessors(bytes32 merkleRoot) external view returns (uint256 successors)
```

## IKeyringCredentials

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### CredentialsDeployed

```solidity
event CredentialsDeployed(address deployer, address trustedForwarder, address policyManager)
```

### CredentialsInitialized

```solidity
event CredentialsInitialized(address admin)
```

### TearDownAdmissionPolicyCredentials

```solidity
event TearDownAdmissionPolicyCredentials(address sender, uint32 policyId)
```

### UpdateCredential

```solidity
event UpdateCredential(uint8 version, address updater, address trader, uint32 admissionPolicyId, uint256 admissionPolicyEpoch)
```

### ROLE_CREDENTIAL_UPDATER

```solidity
function ROLE_CREDENTIAL_UPDATER() external view returns (bytes32)
```

### init

```solidity
function init() external
```

### tearDownAdmissionPolicyCredentials

```solidity
function tearDownAdmissionPolicyCredentials(uint32 policyId) external
```

### cache

```solidity
function cache(uint8 version, address trader, uint32 admissionPolicyId, uint256 admissionPolicyEpoch) external view returns (uint256)
```

### setCredential

```solidity
function setCredential(address trader, uint32 admissionPolicyId, uint256 timestamp) external
```

### getCredential

```solidity
function getCredential(uint8 version, address trader, uint32 admissionPolicyId) external view returns (uint256)
```

## IKeyringGuardImmutable

KeyringGuard implementation that uses immutables and presents a simplified modifier.

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### KeyringGuardConfigured

```solidity
event KeyringGuardConfigured(address keyringCredentials, address policyManager, uint32 admissionPolicyId, bytes32 universeRule, bytes32 emptyRule)
```

### getKeyringCredentials

```solidity
function getKeyringCredentials() external view returns (address keyringCredentials)
```

### getKeyringPolicyManager

```solidity
function getKeyringPolicyManager() external view returns (address policyManager)
```

### getKeyringAdmissionPolicyId

```solidity
function getKeyringAdmissionPolicyId() external view returns (uint32 admissionPolicyId)
```

### getKeyringGenesisRules

```solidity
function getKeyringGenesisRules() external view returns (bytes32 universeRuleId, bytes32 emptyRuleId)
```

### checkKeyringCompliance

```solidity
function checkKeyringCompliance(address user) external returns (bool isCompliant)
```

## IKeyringZkCredentialUpdater

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### CredentialUpdaterDeployed

```solidity
event CredentialUpdaterDeployed(address deployer, address trustedForwarder, address keyringCache, address admissionPolicyManager, address keyringZkVerifier)
```

### AdmitIdentityTree

```solidity
event AdmitIdentityTree(address admin, address identityTree)
```

### RemoveIdentityTree

```solidity
event RemoveIdentityTree(address admin, address identityTree)
```

### AcceptCredentialUpdate

```solidity
event AcceptCredentialUpdate(address sender, address trader, struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorizationProof, uint256 rootTime)
```

### ROLE_IDENTITY_TREE_ADMIN

```solidity
function ROLE_IDENTITY_TREE_ADMIN() external view returns (bytes32)
```

### POLICY_MANAGER

```solidity
function POLICY_MANAGER() external view returns (address)
```

### KEYRING_CREDENTIALS

```solidity
function KEYRING_CREDENTIALS() external view returns (address)
```

### KEYRING_ZK_VERIFIER

```solidity
function KEYRING_ZK_VERIFIER() external view returns (address)
```

### updateCredentials

```solidity
function updateCredentials(address attestor, struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorizationProof) external
```

### checkPolicyAndWallet

```solidity
function checkPolicyAndWallet(address trader, uint32 policyId, address attestor) external returns (bool acceptable)
```

### pack12x20

```solidity
function pack12x20(uint32[12] input) external pure returns (uint256 packed)
```

### unpack12x20

```solidity
function unpack12x20(uint256 packed) external pure returns (uint32[12] unpacked)
```

## IKeyringZkVerifier

### IDENTITY_MEMBERSHIP_PROOF_VERIFIER

```solidity
function IDENTITY_MEMBERSHIP_PROOF_VERIFIER() external returns (address)
```

### IDENTITY_CONSTRUCTION_PROOF_VERIFIER

```solidity
function IDENTITY_CONSTRUCTION_PROOF_VERIFIER() external returns (address)
```

### AUTHORIZATION_PROOF_VERIFIER

```solidity
function AUTHORIZATION_PROOF_VERIFIER() external returns (address)
```

### Groth16Proof

```solidity
struct Groth16Proof {
  uint256[2] a;
  uint256[2][2] b;
  uint256[2] c;
}
```

### IdentityConstructionProof

```solidity
struct IdentityConstructionProof {
  struct IKeyringZkVerifier.Groth16Proof proof;
  uint256 identity;
  uint256 policyCommitment;
  uint256 maxAddresses;
}
```

### IdentityMembershipProof

```solidity
struct IdentityMembershipProof {
  struct IKeyringZkVerifier.Groth16Proof proof;
  uint256 root;
  uint256 nullifierHash;
  uint256 signalHash;
  uint256 externalNullifier;
}
```

### IdentityAuthorisationProof

```solidity
struct IdentityAuthorisationProof {
  struct IKeyringZkVerifier.Groth16Proof proof;
  uint256 externalNullifier;
  uint256 nullifierHash;
  uint256[2] policyDisclosures;
  uint256 tradingAddress;
}
```

### checkClaim

```solidity
function checkClaim(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof) external view returns (bool verified)
```

### checkIdentityConstructionProof

```solidity
function checkIdentityConstructionProof(struct IKeyringZkVerifier.IdentityConstructionProof constructionProof) external view returns (bool verified)
```

### checkIdentityMembershipProof

```solidity
function checkIdentityMembershipProof(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof) external view returns (bool verified)
```

### checkIdentityAuthorisationProof

```solidity
function checkIdentityAuthorisationProof(struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof) external view returns (bool verified)
```

## IKycERC20

Issues wrapped DAI tokens that can only be transferred to holders that maintain
 compliance with the configured policy.

### depositFor

```solidity
function depositFor(address account, uint256 amount) external returns (bool)
```

### withdrawTo

```solidity
function withdrawTo(address account, uint256 amount) external returns (bool)
```

## IPolicyManager

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### PolicyManagerDeployed

```solidity
event PolicyManagerDeployed(address deployer, address trustedForwarder, address ruleRegistry)
```

### PolicyManagerInitialized

```solidity
event PolicyManagerInitialized(address admin)
```

### CreatePolicy

```solidity
event CreatePolicy(address owner, uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, address[] attestors, address[] walletChecks, bytes32 policyOwnerRole, bytes32 policyUserAdminRole)
```

### UpdatePolicyScalar

```solidity
event UpdatePolicyScalar(address owner, uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, uint256 deadline)
```

### UpdatePolicyDescription

```solidity
event UpdatePolicyDescription(address owner, uint32 policyId, string description, uint256 deadline)
```

### UpdatePolicyRuleId

```solidity
event UpdatePolicyRuleId(address owner, uint32 policyId, bytes32 ruleId, uint256 deadline)
```

### UpdatePolicyGracePeriod

```solidity
event UpdatePolicyGracePeriod(address owner, uint32 policyId, uint128 gracePeriod, uint256 deadline)
```

### UpdatePolicyDeadline

```solidity
event UpdatePolicyDeadline(address owner, uint32 policyId, uint256 deadline)
```

### UpdatePolicyLock

```solidity
event UpdatePolicyLock(address owner, uint32 policyId, uint256 deadline)
```

### UpdatePolicyTtl

```solidity
event UpdatePolicyTtl(address owner, uint32 policyId, uint128 ttl, uint256 deadline)
```

### AddPolicyAttestors

```solidity
event AddPolicyAttestors(address owner, uint32 policyId, address[] attestors, uint256 deadline)
```

### RemovePolicyAttestors

```solidity
event RemovePolicyAttestors(address owner, uint32 policyId, address[] attestor, uint256 deadline)
```

### AddPolicyWalletChecks

```solidity
event AddPolicyWalletChecks(address owner, uint32 policyId, address[] walletChecks, uint256 deadline)
```

### RemovePolicyWalletChecks

```solidity
event RemovePolicyWalletChecks(address owner, uint32 policyId, address[] walletChecks, uint256 deadline)
```

### UpdatePolicyAcceptRoots

```solidity
event UpdatePolicyAcceptRoots(address owner, uint32 policyId, uint16 acceptRoots, uint256 deadline)
```

### PolicyLocked

```solidity
event PolicyLocked(address owner, uint32 policyId, uint256 deadline)
```

### PolicyLockCancelled

```solidity
event PolicyLockCancelled(address owner, uint32 policyId, uint256 deadline)
```

### AdmitAttestor

```solidity
event AdmitAttestor(address admin, address attestor, string uri)
```

### UpdateAttestorUri

```solidity
event UpdateAttestorUri(address admin, address attestor, string uri)
```

### RemoveAttestor

```solidity
event RemoveAttestor(address admin, address attestor)
```

### AdmitWalletCheck

```solidity
event AdmitWalletCheck(address admin, address walletCheck)
```

### RemoveWalletCheck

```solidity
event RemoveWalletCheck(address admin, address walletCheck)
```

### SetUserPolicy

```solidity
event SetUserPolicy(address user, uint32 policyId)
```

### SEED_POLICY_OWNER

```solidity
function SEED_POLICY_OWNER() external view returns (bytes32)
```

### ROLE_POLICY_CREATOR

```solidity
function ROLE_POLICY_CREATOR() external view returns (bytes32)
```

### ROLE_GLOBAL_ATTESTOR_ADMIN

```solidity
function ROLE_GLOBAL_ATTESTOR_ADMIN() external view returns (bytes32)
```

### ROLE_GLOBAL_WALLETCHECK_ADMIN

```solidity
function ROLE_GLOBAL_WALLETCHECK_ADMIN() external view returns (bytes32)
```

### ruleRegistry

```solidity
function ruleRegistry() external view returns (address)
```

### init

```solidity
function init() external
```

### createPolicy

```solidity
function createPolicy(struct PolicyStorage.PolicyScalar policyScalar, address[] attestors, address[] walletChecks) external returns (uint32 policyId, bytes32 policyOwnerRoleId, bytes32 policyUserAdminRoleId)
```

### updatePolicyScalar

```solidity
function updatePolicyScalar(uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, uint256 deadline) external
```

### updatePolicyDescription

```solidity
function updatePolicyDescription(uint32 policyId, string descriptionUtf8, uint256 deadline) external
```

### updatePolicyRuleId

```solidity
function updatePolicyRuleId(uint32 policyId, bytes32 ruleId, uint256 deadline) external
```

### updatePolicyTtl

```solidity
function updatePolicyTtl(uint32 policyId, uint32 ttl, uint256 deadline) external
```

### updatePolicyGracePeriod

```solidity
function updatePolicyGracePeriod(uint32 policyId, uint32 gracePeriod, uint256 deadline) external
```

### setDeadline

```solidity
function setDeadline(uint32 policyId, uint256 deadline) external
```

### lockPolicy

```solidity
function lockPolicy(uint32 policyId, uint256 deadline) external
```

### cancelLockPolicy

```solidity
function cancelLockPolicy(uint32 policyId, uint256 deadline) external
```

### addPolicyAttestors

```solidity
function addPolicyAttestors(uint32 policyId, address[] attestors, uint256 deadline) external
```

### removePolicyAttestors

```solidity
function removePolicyAttestors(uint32 policyId, address[] attestors, uint256 deadline) external
```

### addPolicyWalletChecks

```solidity
function addPolicyWalletChecks(uint32 policyId, address[] walletChecks, uint256 deadline) external
```

### removePolicyWalletChecks

```solidity
function removePolicyWalletChecks(uint32 policyId, address[] walletChecks, uint256 deadline) external
```

### setUserPolicy

```solidity
function setUserPolicy(uint32 policyId) external
```

### admitAttestor

```solidity
function admitAttestor(address attestor, string uri) external
```

### updateAttestorUri

```solidity
function updateAttestorUri(address attestor, string uri) external
```

### removeAttestor

```solidity
function removeAttestor(address attestor) external
```

### admitWalletCheck

```solidity
function admitWalletCheck(address walletCheck) external
```

### removeWalletCheck

```solidity
function removeWalletCheck(address walletCheck) external
```

### userPolicy

```solidity
function userPolicy(address user) external view returns (uint32 policyId)
```

### policy

```solidity
function policy(uint32 policyId) external returns (struct PolicyStorage.PolicyScalar scalar, address[] attestors, address[] walletChecks, uint256 deadline)
```

### policyRawData

```solidity
function policyRawData(uint32 policyId) external view returns (uint256 deadline, struct PolicyStorage.PolicyScalar scalarActive, struct PolicyStorage.PolicyScalar scalarPending, address[] attestorsActive, address[] attestorsPendingAdditions, address[] attestorsPendingRemovals, address[] walletChecksActive, address[] walletChecksPendingAdditions, address[] walletChecksPendingRemovals)
```

### policyOwnerRole

```solidity
function policyOwnerRole(uint32 policyId) external pure returns (bytes32 ownerRole)
```

### policyRuleId

```solidity
function policyRuleId(uint32 policyId) external returns (bytes32 ruleId)
```

### policyDescription

```solidity
function policyDescription(uint32 policyId) external returns (string description)
```

### policyAcceptRoots

```solidity
function policyAcceptRoots(uint32 policyId) external returns (uint16 acceptRoots)
```

### policyTtl

```solidity
function policyTtl(uint32 policyId) external returns (uint128 ttl)
```

### policyLocked

```solidity
function policyLocked(uint32 policyId) external returns (bool isLocked)
```

### policyGracePeriod

```solidity
function policyGracePeriod(uint32 policyId) external returns (uint128 gracePeriod)
```

### policyAttestorCount

```solidity
function policyAttestorCount(uint32 policyId) external returns (uint256 count)
```

### policyAttestorAtIndex

```solidity
function policyAttestorAtIndex(uint32 policyId, uint256 index) external returns (address attestor)
```

### policyAttestors

```solidity
function policyAttestors(uint32 policyId) external returns (address[] attestors)
```

### isPolicyAttestor

```solidity
function isPolicyAttestor(uint32 policyId, address attestor) external returns (bool isIndeed)
```

### policyWalletCheckCount

```solidity
function policyWalletCheckCount(uint32 policyId) external returns (uint256 count)
```

### policyWalletCheckAtIndex

```solidity
function policyWalletCheckAtIndex(uint32 policyId, uint256 index) external returns (address walletCheck)
```

### policyWalletChecks

```solidity
function policyWalletChecks(uint32 policyId) external returns (address[] walletChecks)
```

### isPolicyWalletCheck

```solidity
function isPolicyWalletCheck(uint32 policyId, address walletCheck) external returns (bool isIndeed)
```

### policyCount

```solidity
function policyCount() external view returns (uint256 count)
```

### isPolicy

```solidity
function isPolicy(uint32 policyId) external view returns (bool isIndeed)
```

### globalAttestorCount

```solidity
function globalAttestorCount() external view returns (uint256 count)
```

### globalAttestorAtIndex

```solidity
function globalAttestorAtIndex(uint256 index) external view returns (address attestor)
```

### isGlobalAttestor

```solidity
function isGlobalAttestor(address attestor) external view returns (bool isIndeed)
```

### globalWalletCheckCount

```solidity
function globalWalletCheckCount() external view returns (uint256 count)
```

### globalWalletCheckAtIndex

```solidity
function globalWalletCheckAtIndex(uint256 index) external view returns (address walletCheck)
```

### isGlobalWalletCheck

```solidity
function isGlobalWalletCheck(address walletCheck) external view returns (bool isIndeed)
```

### attestorUri

```solidity
function attestorUri(address attestor) external view returns (string)
```

### hasRole

```solidity
function hasRole(bytes32 role, address user) external view returns (bool)
```

## IRuleRegistry

### Operator

```solidity
enum Operator {
  Base,
  Union,
  Intersection,
  Complement
}
```

### Rule

```solidity
struct Rule {
  string description;
  string uri;
  enum IRuleRegistry.Operator operator;
  struct Bytes32Set.Set operandSet;
  bool toxic;
}
```

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### RuleRegistryDeployed

```solidity
event RuleRegistryDeployed(address deployer, address trustedForwarder)
```

### RuleRegistryInitialized

```solidity
event RuleRegistryInitialized(address admin, string universeDescription, string universeUri, string emptyDescription, string emptyUri, bytes32 universeRule, bytes32 emptyRule)
```

### CreateRule

```solidity
event CreateRule(address user, bytes32 ruleId, string description, string uri, bool toxic, enum IRuleRegistry.Operator operator, bytes32[] operands)
```

### SetToxic

```solidity
event SetToxic(address admin, bytes32 ruleId, bool isToxic)
```

### ROLE_RULE_ADMIN

```solidity
function ROLE_RULE_ADMIN() external view returns (bytes32)
```

### init

```solidity
function init(string universeDescription, string universeUri, string emptyDescription, string emptyUri) external
```

### createRule

```solidity
function createRule(string description, string uri, enum IRuleRegistry.Operator operator, bytes32[] operands) external returns (bytes32 ruleId)
```

### setToxic

```solidity
function setToxic(bytes32 ruleId, bool toxic) external
```

### genesis

```solidity
function genesis() external view returns (bytes32 universeRule, bytes32 emptyRule)
```

### ruleCount

```solidity
function ruleCount() external view returns (uint256 count)
```

### ruleAtIndex

```solidity
function ruleAtIndex(uint256 index) external view returns (bytes32 ruleId)
```

### isRule

```solidity
function isRule(bytes32 ruleId) external view returns (bool isIndeed)
```

### rule

```solidity
function rule(bytes32 ruleId) external view returns (string description, string uri, enum IRuleRegistry.Operator operator, uint256 operandCount)
```

### ruleDescription

```solidity
function ruleDescription(bytes32 ruleId) external view returns (string description)
```

### ruleUri

```solidity
function ruleUri(bytes32 ruleId) external view returns (string uri)
```

### ruleIsToxic

```solidity
function ruleIsToxic(bytes32 ruleId) external view returns (bool isIndeed)
```

### ruleOperator

```solidity
function ruleOperator(bytes32 ruleId) external view returns (enum IRuleRegistry.Operator operator)
```

### ruleOperandCount

```solidity
function ruleOperandCount(bytes32 ruleId) external view returns (uint256 count)
```

### ruleOperandAtIndex

```solidity
function ruleOperandAtIndex(bytes32 ruleId, uint256 index) external view returns (bytes32 operandId)
```

### generateRuleId

```solidity
function generateRuleId(string description, enum IRuleRegistry.Operator operator, bytes32[] operands) external pure returns (bytes32 ruleId)
```

## IWalletCheck

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### SetWalletFlag

```solidity
event SetWalletFlag(address admin, address wallet, bool isFlagged)
```

### ROLE_WALLET_CHECK_ADMIN

```solidity
function ROLE_WALLET_CHECK_ADMIN() external view returns (bytes32)
```

### isFlagged

```solidity
function isFlagged(address wallet) external view returns (bool isFlagged)
```

### setWalletFlag

```solidity
function setWalletFlag(address wallet, bool flagged) external
```

## KeyringCredentials

Holds the time-limited credential cache, organized by user and admission policy. 
 The credentials are non-transferrable and are represented as timestamps. Non-zero 
 entries indicate that an authorized credential updater such as the KeyringZkCredentialUpdater
 accepted evidence of compliance and recorded it here with a timestamp to indicate the 
 start time to use for calculating the credential's age.

### ROLE_CREDENTIAL_UPDATER

```solidity
bytes32 ROLE_CREDENTIAL_UPDATER
```

### policyManager

```solidity
address policyManager
```

### policyEpochs

```solidity
mapping(uint32 => uint256) policyEpochs
```

_Epochs enable immediate and O(1) destruction of all cached credentials for a single policy. This
     is a contingency function for extraordinary circumstances. For example, ejecting especially troublesome
     users with cached credentials with immediate effect by forcing everyone to attempt to gather new
     attestations and refresh their cached credentials if they want to interact with the subject policy._

### cache

```solidity
mapping(uint8 => mapping(address => mapping(uint32 => mapping(uint256 => uint256)))) cache
```

_The credentials are indexed by (version => trader => admissionPolicyId => epoch) => updateTime
     where the version is always 1 and the epoch supports emergency tear-down of all cached credentials
     for a given policy, if the policy owner orders it._

### onlyUpdater

```solidity
modifier onlyUpdater()
```

Revert if the message sender doesn't have the Credentials updater role.

### onlyPolicyAdmin

```solidity
modifier onlyPolicyAdmin(uint32 policyId)
```

Only the PolicyAdmin can tear down user credentials.

### constructor

```solidity
constructor(address trustedForwarder, address policyManager_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| policyManager_ | address |  |

### init

```solidity
function init() external
```

This upgradeable contract must be initialized.
     @dev The initializer function MUST be called directly after deployment 
     because anyone can call it but overall only once.

### tearDownAdmissionPolicyCredentials

```solidity
function tearDownAdmissionPolicyCredentials(uint32 policyId) external
```

The policy admin can invalidate all stored credentials for a given policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy with credentials to tear down |

### setCredential

```solidity
function setCredential(address trader, uint32 admissionPolicyId, uint256 timestamp) external
```

This function is called by a trusted and permitted contract such as the 
     KeyringZkCredentialUpdater. There is no prohibition on multiple proving schemes 
     at the cache level since this contract requires only that the caller has permission.
     @param trader The user address for the Credential update.
     @param admissionPolicyId The unique identifier of a Policy.
     @param timestamp The timestamp established by the credential updater.

### getCredential

```solidity
function getCredential(uint8 version, address trader, uint32 admissionPolicyId) external view returns (uint256 timestamp)
```

Inspect the credential cache.
     @param version Cache organization version.
     @param trader The user to inspect.
     @param admissionPolicyId The admission policy for the credential to inspect.
     @return timestamp The timestamp established when the credential was recorded.

## KeyringZkVerifier

Binds the on-chain zero-knowledge verifiers, which are generated from circuits, together and
 applies additional constraints such as requiring that users generate membership proofs and
 authorization proofs from the same identity commitments. Includes a function inspect identity
 commitments and confirm correct construction. This is presumed to occur before identity commitments
 are included in identity trees and is thus a courtesy function in service to the aggregator which is
 required to validate identity commitments submmitted by authorization wallets.

### IDENTITY_MEMBERSHIP_PROOF_VERIFIER

```solidity
address IDENTITY_MEMBERSHIP_PROOF_VERIFIER
```

### IDENTITY_CONSTRUCTION_PROOF_VERIFIER

```solidity
address IDENTITY_CONSTRUCTION_PROOF_VERIFIER
```

### AUTHORIZATION_PROOF_VERIFIER

```solidity
address AUTHORIZATION_PROOF_VERIFIER
```

### constructor

```solidity
constructor(address identityConstructionProofVerifier, address membershipProofVerifier, address authorisationProofVerifier) public
```

### checkClaim

```solidity
function checkClaim(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof) external view returns (bool verified)
```

Check membership and authorization proofs using circom verifiers. Both proofs must be
     generated from the same identity commitment. 
     @param membershipProof Proof of inclusion in an identity tree.
     @param authorisationProof Proof of policyId inclusions in the identity commitment.
     @return verified True if the claim is valid.

### checkIdentityConstructionProof

```solidity
function checkIdentityConstructionProof(struct IKeyringZkVerifier.IdentityConstructionProof constructionProof) external view returns (bool verified)
```

Check correct construction of an identity commitment.
     @param constructionProof Proof of correct construction of the identity commitment as defined in 
     IKeyringZkVerifier.
     @return verified True if the construction proof is valid.

### checkIdentityMembershipProof

```solidity
function checkIdentityMembershipProof(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof) public view returns (bool verified)
```

Check that the identity commitment is a member of the identity tree.
     @param membershipProof Proof of membership as defined in IKeyringZkVerifier.
     @return verified True if the identity commitment is a member of the identity tree.

### checkIdentityAuthorisationProof

```solidity
function checkIdentityAuthorisationProof(struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof) public view returns (bool verified)
```

Check that the policies disclosed are included in the identity commitment.
     @param authorisationProof Proof of authorisation as defined in IKeyringZkVerifier.
     @return verified True if the trader wallet is authorised for all policies in the disclosure.

## AddressSet

Key sets with enumeration and delete. Uses mappings for random access and existence checks,
and dynamic arrays for enumeration. Key uniqueness is enforced.

_Sets are unordered. Delete operations reorder keys._

### Set

```solidity
struct Set {
  mapping(address => uint256) keyPointers;
  address[] keyList;
}
```

### AddressSetConsistency

```solidity
error AddressSetConsistency(string module, string method, string reason, string context)
```

### insert

```solidity
function insert(struct AddressSet.Set self, address key, string context) internal
```

Insert a key to store.

_Duplicate keys are not permitted._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | An Set struct - similar syntax to python classes. |
| key | address | An key to insert cast as an address. |
| context | string | A message string about interpretation of the issue. Normally the calling function. |

### remove

```solidity
function remove(struct AddressSet.Set self, address key, string context) internal
```

Remove a key from the store.

_The key to remove must exist._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Set struct - similar syntax to python classes. |
| key | address | An address to remove from the Set. |
| context | string | A message string about interpretation of the issue. Normally the calling function. |

### count

```solidity
function count(struct AddressSet.Set self) internal view returns (uint256)
```

Count the keys.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Set struct - similar syntax to python classes. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | uint256 | uint256 Length of the `keyList`, which correspond to the number of elements stored in the `keyPointers` mapping. |

### exists

```solidity
function exists(struct AddressSet.Set self, address key) internal view returns (bool)
```

Check if a key exists in the Set.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Set struct - similar syntax to python classes |
| key | address | An address to look for in the Set. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool True if the key exists in the Set, otherwise false. |

### keyAtIndex

```solidity
function keyAtIndex(struct AddressSet.Set self, uint256 index) internal view returns (address)
```

Retrieve an address by its position in the set. Use for enumeration.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Set struct - similar syntax to python classes. |
| index | uint256 | The internal index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | address | address Address value stored at the index position in the Set. |

## Bytes32Set

Key sets with enumeration. Uses mappings for random and existence checks
and dynamic arrays for enumeration. Key uniqueness is enforced.

_This implementation has deletion disabled (removed) because doesn't require it. Therefore, keys
 are organized in order of insertion._

### Set

```solidity
struct Set {
  mapping(bytes32 => uint256) keyPointers;
  bytes32[] keyList;
}
```

### SetConsistency

```solidity
error SetConsistency(string module, string method, string reason, string context)
```

### insert

```solidity
function insert(struct Bytes32Set.Set self, bytes32 key, string context) internal
```

Insert a key to store.

_Duplicate keys are not permitted._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Set struct - similar syntax to python classes. |
| key | bytes32 | A value in the Set. |
| context | string | A message string about interpretation of the issue. Normally the calling function. |

### count

```solidity
function count(struct Bytes32Set.Set self) internal view returns (uint256)
```

Count the keys.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Set struct - similar syntax to python classes. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | uint256 | uint256 Length of the `keyList` which is the count of keys contained in the Set. |

### exists

```solidity
function exists(struct Bytes32Set.Set self, bytes32 key) internal view returns (bool)
```

Check if a key exists in the Set.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Set struct - similar syntax to python classes. |
| key | bytes32 | A key to look for. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool True if the key exists in the Set, otherwise false. |

### keyAtIndex

```solidity
function keyAtIndex(struct Bytes32Set.Set self, uint256 index) internal view returns (bytes32)
```

Retrieve an bytes32 by its position in the Set. Use for enumeration.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Set struct - similar syntax to python classes. |
| index | uint256 | The position in the Set to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bytes32 | bytes32 The key stored in the Set at the index position. |

## PackLib

### FIELD_SIZE

```solidity
uint8 FIELD_SIZE
```

### MASK

```solidity
uint256 MASK
```

### pack

```solidity
function pack(uint32[12] input) internal pure returns (uint256 packed)
```

Pack 12 20-bit integers into a 240-bit object.
     @dev uint32 Inputs are truncated above 20 bits of magnitude.
     @param input Array of 20-bit integers to pack cast as an array of uint32.

### unpack

```solidity
function unpack(uint256 packed) public pure returns (uint32[12] output)
```

Unpack 12 20-bit integers from 240-bit input
     @dev Data beyond the first 240 bits is ignored.
     @param packed 12 20-bit integers packed into 240 bits.
     @return output 12 20-bit integers cast as an array of 32-bit integers.

## PolicyStorage

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### App

```solidity
struct App {
  struct PolicyStorage.Policy[] policies;
  mapping(address => uint32) userPolicies;
  struct AddressSet.Set globalAttestorSet;
  mapping(address => string) attestorUris;
  struct AddressSet.Set globalWalletCheckSet;
}
```

### PolicyScalar

```solidity
struct PolicyScalar {
  bytes32 ruleId;
  string descriptionUtf8;
  uint32 ttl;
  uint32 gracePeriod;
  uint16 acceptRoots;
  bool locked;
}
```

### PolicyAttestors

```solidity
struct PolicyAttestors {
  struct AddressSet.Set activeSet;
  struct AddressSet.Set pendingAdditionSet;
  struct AddressSet.Set pendingRemovalSet;
}
```

### PolicyWalletChecks

```solidity
struct PolicyWalletChecks {
  struct AddressSet.Set activeSet;
  struct AddressSet.Set pendingAdditionSet;
  struct AddressSet.Set pendingRemovalSet;
}
```

### Policy

```solidity
struct Policy {
  uint256 deadline;
  struct PolicyStorage.PolicyScalar scalarActive;
  struct PolicyStorage.PolicyScalar scalarPending;
  struct PolicyStorage.PolicyAttestors attestors;
  struct PolicyStorage.PolicyWalletChecks walletChecks;
}
```

### insertGlobalAttestor

```solidity
function insertGlobalAttestor(struct PolicyStorage.App self, address attestor, string uri) public
```

### updateGlobalAttestorUri

```solidity
function updateGlobalAttestorUri(struct PolicyStorage.App self, address attestor, string uri) public
```

### removeGlobalAttestor

```solidity
function removeGlobalAttestor(struct PolicyStorage.App self, address attestor) public
```

### insertGlobalWalletCheck

```solidity
function insertGlobalWalletCheck(struct PolicyStorage.App self, address walletCheck) public
```

### removeGlobalWalletCheck

```solidity
function removeGlobalWalletCheck(struct PolicyStorage.App self, address walletCheck) public
```

### setUserPolicy

```solidity
function setUserPolicy(struct PolicyStorage.App self, address user, uint32 userPolicyId) public
```

### userPolicy

```solidity
function userPolicy(struct PolicyStorage.App self, address user) public view returns (uint32 policyId)
```

### newPolicy

```solidity
function newPolicy(struct PolicyStorage.App self, struct PolicyStorage.PolicyScalar policyScalar, address[] attestors, address[] walletChecks, address ruleRegistry) public returns (uint32 policyId)
```

### policyRawData

```solidity
function policyRawData(struct PolicyStorage.App self, uint32 policyId) public view returns (struct PolicyStorage.Policy policyInfo)
```

### processStaged

```solidity
function processStaged(struct PolicyStorage.Policy policyIn) public returns (struct PolicyStorage.Policy policy)
```

### isPolicy

```solidity
function isPolicy(struct PolicyStorage.App self, uint32 policyId) public view returns (bool isIndeed)
```

### checkLock

```solidity
function checkLock(struct PolicyStorage.Policy policy) public view
```

### isLocked

```solidity
function isLocked(struct PolicyStorage.Policy policy) public view returns (bool isIndeed)
```

### setDeadline

```solidity
function setDeadline(struct PolicyStorage.Policy policyIn, uint256 deadline) public returns (struct PolicyStorage.Policy policy)
```

### writePolicyScalar

```solidity
function writePolicyScalar(struct PolicyStorage.App self, uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, address ruleRegistry, uint256 deadline) public
```

### writeRuleId

```solidity
function writeRuleId(struct PolicyStorage.Policy self, bytes32 ruleId, address ruleRegistry) public
```

### writeDescription

```solidity
function writeDescription(struct PolicyStorage.Policy self, string descriptionUtf8) public
```

### writeTtl

```solidity
function writeTtl(struct PolicyStorage.Policy self, uint32 ttl) public
```

### writeGracePeriod

```solidity
function writeGracePeriod(struct PolicyStorage.Policy self, uint32 gracePeriod) public
```

### writePolicyLock

```solidity
function writePolicyLock(struct PolicyStorage.Policy self, bool setPolicyLocked) public
```

### writeAcceptRoots

```solidity
function writeAcceptRoots(struct PolicyStorage.Policy self, uint16 acceptRoots) public
```

### writeAttestorAdditions

```solidity
function writeAttestorAdditions(struct PolicyStorage.App self, struct PolicyStorage.Policy policy, address[] attestors) public
```

### writeAttestorRemovals

```solidity
function writeAttestorRemovals(struct PolicyStorage.Policy self, address[] attestors) public
```

### writeWalletCheckAdditions

```solidity
function writeWalletCheckAdditions(struct PolicyStorage.App self, struct PolicyStorage.Policy policy, address[] walletChecks) public
```

### writeWalletCheckRemovals

```solidity
function writeWalletCheckRemovals(struct PolicyStorage.Policy self, address[] walletChecks) public
```

## MockERC20

### constructor

```solidity
constructor(string _name, string _symbol, uint256 _supply) public
```

## MockRuleRegistry

The RuleRegistry holds the global list of all existing Policy rules, which
can be applied in the PolicyManager contract via the createPolicy and updatePolicy
functions. Base Rules are managed by the Rule Admin role. Anyone can create an
expression using an operator and existing Rules as operands.

### ROLE_RULE_ADMIN

```solidity
bytes32 ROLE_RULE_ADMIN
```

### constructor

```solidity
constructor(address trustedForwarder, bytes32 universeRule, bytes32 emptyRule) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| universeRule | bytes32 |  |
| emptyRule | bytes32 |  |

### init

```solidity
function init(string universeDescription, string universeUri, string emptyDescription, string emptyUri) external
```

This upgradeable contract must be initialized.

_Initialiser function MUST be called directly after deployment
     because anyone can call it but overall only once._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| universeDescription | string | Description of the universal set Rule. |
| universeUri | string | The universal set URI. |
| emptyDescription | string | Description of the empty Rule. |
| emptyUri | string | The empty Rule URI. |

### createRule

```solidity
function createRule(string description, string uri, enum IRuleRegistry.Operator operator, bytes32[] operands) public returns (bytes32 ruleId)
```

Anyone can create expressions. Only the Rule Admin can create Base Rules.

_Interpretation of Expressions is deterministic._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| description | string | The description for a Base Rule. Empty for expressions. |
| uri | string | Detailed information Uri for a Base Rule. Empty for expressions. |
| operator | enum IRuleRegistry.Operator | The expression operator (1-3, or Base (0) |
| operands | bytes32[] | The list of the ruleId’s in the expression. Empty for Base Rules. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The unique identifier of Rule. Each Policy has exactly one Rule. |

### setToxic

```solidity
function setToxic(bytes32 ruleId, bool toxic) external
```

The rule admin can adjust the toxic flag

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The rule to update |
| toxic | bool | True if the rule is to be set as toxic |

### genesis

```solidity
function genesis() external view returns (bytes32 universeRuleId, bytes32 emptyRuleId)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| universeRuleId | bytes32 | The id of the universal set (everyone) Rule.      @return emptyRuleId The id of the empty (no one) Rule. |
| emptyRuleId | bytes32 |  |

### ruleCount

```solidity
function ruleCount() external view returns (uint256 count)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Number of existing Rules in the global list. |

### ruleAtIndex

```solidity
function ruleAtIndex(uint256 index) external view returns (bytes32 ruleId)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | Iterate rules in the global list. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Id of a rule in the global list. |

### isRule

```solidity
function isRule(bytes32 ruleId) public view returns (bool isIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The unique identifier of a rule. Each Policy has exactly one rule. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True value if Rule exists, otherwise False. |

### rule

```solidity
function rule(bytes32 ruleId) external view returns (string description, string uri, enum IRuleRegistry.Operator operator, uint256 operandCount)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The unique identifier of a rule. Each Policy has exactly one rule. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| description | string | The description for a Base Rule. |
| uri | string | Base Rule uri refers to detailed information about the Rule. |
| operator | enum IRuleRegistry.Operator | The expression operator (0-4), or Base (0) |
| operandCount | uint256 | The number of operands. 0 for Base rules. |

### ruleDescription

```solidity
function ruleDescription(bytes32 ruleId) external view returns (string description)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| description | string | The Rule description. |

### ruleUri

```solidity
function ruleUri(bytes32 ruleId) external view returns (string uri)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| uri | string | The Rule uri. |

### ruleIsToxic

```solidity
function ruleIsToxic(bytes32 ruleId) public view returns (bool isIndeed)
```

Toxic rules can be used in policies without approval

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The rule to inspect |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the rule is toxic |

### ruleOperator

```solidity
function ruleOperator(bytes32 ruleId) external view returns (enum IRuleRegistry.Operator operator)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| operator | enum IRuleRegistry.Operator | The Rule operator. |

### ruleOperandCount

```solidity
function ruleOperandCount(bytes32 ruleId) external view returns (uint256 count)
```

_Does not check Rule existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The number of operands in the Rule expression. |

### ruleOperandAtIndex

```solidity
function ruleOperandAtIndex(bytes32 ruleId, uint256 index) external view returns (bytes32 operandId)
```

_Does not check Rule existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |
| index | uint256 | The operand list row to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| operandId | bytes32 | A Rule id. |

### generateRuleId

```solidity
function generateRuleId(string description, enum IRuleRegistry.Operator operator, bytes32[] operands) public pure returns (bytes32 ruleId)
```

Generate a deterministic ruleId

_Warning: This does not validate the inputs_

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The ruleId that will be generated if the configuration is valid |

## PolicyManager

PolicyManager holds the policies managed by DeFi Protocol Operators and users. 
 When used by a KeyringGuard, policies describe admission policies that will be enforced. 
 When used by a user, policies describe the rules that compliant DeFi Protocol Operators 
 must enforce in order for their contracts to be compatible with the user policy.

### SEED_POLICY_OWNER

```solidity
bytes32 SEED_POLICY_OWNER
```

### ROLE_POLICY_CREATOR

```solidity
bytes32 ROLE_POLICY_CREATOR
```

### ROLE_GLOBAL_ATTESTOR_ADMIN

```solidity
bytes32 ROLE_GLOBAL_ATTESTOR_ADMIN
```

### ROLE_GLOBAL_WALLETCHECK_ADMIN

```solidity
bytes32 ROLE_GLOBAL_WALLETCHECK_ADMIN
```

### ruleRegistry

```solidity
address ruleRegistry
```

### policyStorage

```solidity
struct PolicyStorage.App policyStorage
```

### onlyPolicyAdmin

```solidity
modifier onlyPolicyAdmin(uint32 policyId)
```

The policy admin role is initially granted during createPolicy.

_Reverts if the msg signer doesn't have the policy admin role._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

### onlyPolicyCreator

```solidity
modifier onlyPolicyCreator()
```

Only policy creators can create new policies.

_Reverts if the user doesn't have the policy creator role._

### onlyAttestorAdmin

```solidity
modifier onlyAttestorAdmin()
```

Keyring Governance has exclusive control of the global whitelist of Attestors.

_Reverts if the user doesn't have the global attestor admin role._

### onlyWalletCheckAdmin

```solidity
modifier onlyWalletCheckAdmin()
```

Keyring Governance has exclusive access to the global whitelist of Wallet Checks.

_Reverts if the user doesn't have the global wallet check admin role._

### constructor

```solidity
constructor(address trustedForwarder, address ruleRegistryAddr) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| ruleRegistryAddr | address | The address of the deployed RuleRegistry contract. |

### init

```solidity
function init() external
```

This upgradeable contract must be initialized.

_Initializer function MUST be called directly after deployment.
     because anyone can call it but overall only once._

### createPolicy

```solidity
function createPolicy(struct PolicyStorage.PolicyScalar policyScalar, address[] attestors, address[] walletChecks) external returns (uint32 policyId, bytes32 policyOwnerRoleId, bytes32 policyUserAdminRoleId)
```

A policy creater can create a policy and is granted the admin and user admin roles.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyScalar | struct PolicyStorage.PolicyScalar | The policy object scalar values as defined in PolicyStorage. |
| attestors | address[] | Acceptable attestors correspond to identity trees that will be used in      zero-knowledge proofs. Proofs cannot be generated, and therefore credentials cannot be      generated using roots that do not originate in an identity tree that is not explicitly      acceptable. |
| walletChecks | address[] | Trader wallets are optionally checked againt on-chain wallet checks on      a just-in-time basis. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a new Policy. |
| policyOwnerRoleId | bytes32 |  |
| policyUserAdminRoleId | bytes32 |  |

### updatePolicyScalar

```solidity
function updatePolicyScalar(uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, uint256 deadline) external
```

The Policy admin role can update a policy's scalar values one step.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |
| policyScalar | struct PolicyStorage.PolicyScalar | The policy definition scalar values. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyRuleId

```solidity
function updatePolicyRuleId(uint32 policyId, bytes32 ruleId, uint256 deadline) external
```

Policy admins can update policy rules.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| ruleId | bytes32 | The new policy rule. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyDescription

```solidity
function updatePolicyDescription(uint32 policyId, string descriptionUtf8, uint256 deadline) external
```

Policy admins can update policy descriptions.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| descriptionUtf8 | string | The new policy description. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyTtl

```solidity
function updatePolicyTtl(uint32 policyId, uint32 ttl, uint256 deadline) external
```

Policy admins can update policy credential expiry times.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| ttl | uint32 | The maximum acceptable credential age in seconds. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyGracePeriod

```solidity
function updatePolicyGracePeriod(uint32 policyId, uint32 gracePeriod, uint256 deadline) external
```

Policy admins can change the gracePeriod with delayed effect.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| gracePeriod | uint32 | The minimum acceptable deadline. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyAcceptRoots

```solidity
function updatePolicyAcceptRoots(uint32 policyId, uint16 acceptRoots, uint256 deadline) external
```

Policy admins can force acceptance of the last n identity tree roots. This facility
     provides protection for traders in the event that circumstances prevent the publication of 
     new identity tree roots.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| acceptRoots | uint16 | The depth of most recent roots to always accept. |
| deadline | uint256 |  |

### lockPolicy

```solidity
function lockPolicy(uint32 policyId, uint256 deadline) external
```

Schedules policy locking if the policy is not already scheduled to be locked.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to lock. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### cancelLockPolicy

```solidity
function cancelLockPolicy(uint32 policyId, uint256 deadline) external
```

Unschedules policy locking.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to abort locking. |
| deadline | uint256 | Overrides previous deadline. |

### setDeadline

```solidity
function setDeadline(uint32 policyId, uint256 deadline) external
```

Update the deadline for staged policy changes to take effect.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to update. |
| deadline | uint256 | Must be >= graceTime seconds past block time or 0 to unschedule staged policy changes. |

### addPolicyAttestors

```solidity
function addPolicyAttestors(uint32 policyId, address[] attestors, uint256 deadline) external
```

The Policy admin selects whitelisted Attestors that are acceptable for their Policy.

_Deadlines must always be >= the active policy grace period. Attestors must be absent from
     the active attestors set, or present in the staged removals._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| attestors | address[] | The address of one or more Attestors to add to the Policy. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### removePolicyAttestors

```solidity
function removePolicyAttestors(uint32 policyId, address[] attestors, uint256 deadline) external
```

The Policy admin selects whitelisted Attestors that are acceptable for their Policy.

_Deadlines must always be >= the active policy grace period. The attestors must be present
     in the active attestor set or staged updates._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| attestors | address[] | The address of one or more Attestors to remove from the Policy. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### addPolicyWalletChecks

```solidity
function addPolicyWalletChecks(uint32 policyId, address[] walletChecks, uint256 deadline) external
```

The Policy admin selects whitelisted Attestors that are acceptable for their Policy.

_Deadlines must always be >= the active policy grace period. The wallet checks must be absent
     from the active wallet check set, or present in the staged removals._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| walletChecks | address[] | The address of one or more Wallet Checks to add to the Policy. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### removePolicyWalletChecks

```solidity
function removePolicyWalletChecks(uint32 policyId, address[] walletChecks, uint256 deadline) external
```

The Policy admin selects whitelisted Attestors that are acceptable for their Policy.

_Deadlines must always be >= the active policy grace period. The wallet checks must be present
     in the active wallet checks set or staged additions._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| walletChecks | address[] | The address of one or more Attestors to remove from the Policy. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### setUserPolicy

```solidity
function setUserPolicy(uint32 policyId) external
```

Each user sets exactly one Policy that attestors are required to compare with admission 
     policies.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

### admitAttestor

```solidity
function admitAttestor(address attestor, string uri) external
```

The Global Attestor Admin can admit Attestors to the global whitelist.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | The address of a Attestor to admit into the global whitelist. |
| uri | string | The URI refers to detailed information about the attestor. |

### updateAttestorUri

```solidity
function updateAttestorUri(address attestor, string uri) external
```

The Global Attestor Admin can update the uris for Attestors on the global whitelist.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | The address of a Attestor in the global whitelist. |
| uri | string | The new uri for the Attestor. |

### removeAttestor

```solidity
function removeAttestor(address attestor) external
```

The Global Attestor Admin can remove Attestors from the global whitelist.

_Does not automatically remove Attestors from affected Policies._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | The address of an Attestor on the global whitelist. |

### admitWalletCheck

```solidity
function admitWalletCheck(address walletCheck) external
```

The Global Wallet Check Admin can admit Wallet Checks to the global whitelist.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletCheck | address | The address of a Wallet Check to admit into the global whitelist. |

### removeWalletCheck

```solidity
function removeWalletCheck(address walletCheck) external
```

The Global Wallet Check Admin can remove Wallet Checks from the global whitelist.

_Does not automatically remove Wallet Checks from affected Policies._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletCheck | address | The address of a Wallet Check contract in the global whitelist. |

### userPolicy

```solidity
function userPolicy(address user) external view returns (uint32 policyId)
```

Each user has a user policy that is compared to admission policies.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The user to inspect. |

### policy

```solidity
function policy(uint32 policyId) public returns (struct PolicyStorage.PolicyScalar config, address[] attestors, address[] walletChecks, uint256 deadline)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| config | struct PolicyStorage.PolicyScalar | The scalar values that form part of the policy definition. |
| attestors | address[] | The authorized attestors for the policy. |
| walletChecks | address[] | The policy trader wallet checks that will be performed on a just-in-time basis. |
| deadline | uint256 | The timestamp when staged changes will take effect. |

### policyRawData

```solidity
function policyRawData(uint32 policyId) external view returns (uint256 deadline, struct PolicyStorage.PolicyScalar scalarActive, struct PolicyStorage.PolicyScalar scalarPending, address[] attestorsActive, address[] attestorsPendingAdditions, address[] attestorsPendingRemovals, address[] walletChecksActive, address[] walletChecksPendingAdditions, address[] walletChecksPendingRemovals)
```

Reveals the internal state of the policy object without processing staged changes.

_A non-zero deadline in the past indicates that staged updates are already in effect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

### policyOwnerRole

```solidity
function policyOwnerRole(uint32 policyId) public pure returns (bytes32 ownerRole)
```

Generate the corresponding admin/owner role for a policyId

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ownerRole | bytes32 | The bytes32 owner role that corresponds to the policyId |

### policyRuleId

```solidity
function policyRuleId(uint32 policyId) external returns (bytes32 ruleId)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | Rule to enforce, defined in the RuleRegistry. |

### policyDescription

```solidity
function policyDescription(uint32 policyId) external returns (string descriptionUtf8)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| descriptionUtf8 | string | Not used for any on-chain logic. |

### policyTtl

```solidity
function policyTtl(uint32 policyId) external returns (uint128 ttl)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ttl | uint128 | The maximum age of acceptable credentials. |

### policyGracePeriod

```solidity
function policyGracePeriod(uint32 policyId) external returns (uint128 gracePeriod)
```

Inspect a policy grace period.

_Use static calls to inspect current information._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| gracePeriod | uint128 | Seconds until policy changes take effect. |

### policyAcceptRoots

```solidity
function policyAcceptRoots(uint32 policyId) external returns (uint16 acceptRoots)
```

Check the number of latest identity roots to accept, regardless of age.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| acceptRoots | uint16 | The number of latest identity roots to accept unconditionally for the construction      of zero-knowledge proofs. |

### policyLocked

```solidity
function policyLocked(uint32 policyId) external returns (bool isLocked)
```

Check if the policy is locked.

_Use static calls to inspect current information._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isLocked | bool | True if the policy cannot be changed |

### policyAttestorCount

```solidity
function policyAttestorCount(uint32 policyId) public returns (uint256 count)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The count of acceptable Attestors for the Policy. |

### policyAttestorAtIndex

```solidity
function policyAttestorAtIndex(uint32 policyId, uint256 index) external returns (address attestor)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The Policy to inspect. |
| index | uint256 | The list index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | The address of a Attestor that is acceptable for the Policy. |

### policyAttestors

```solidity
function policyAttestors(uint32 policyId) external returns (address[] attestors)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestors | address[] | The list of attestors that are authoritative for the policy. |

### isPolicyAttestor

```solidity
function isPolicyAttestor(uint32 policyId, address attestor) external returns (bool isIndeed)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The Policy to inspect. |
| attestor | address | The address to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if attestor is acceptable for the Policy, otherwise false. |

### policyWalletCheckCount

```solidity
function policyWalletCheckCount(uint32 policyId) public returns (uint256 count)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The count of wallet checks for the Policy. |

### policyWalletCheckAtIndex

```solidity
function policyWalletCheckAtIndex(uint32 policyId, uint256 index) external returns (address walletCheck)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The Policy to inspect. |
| index | uint256 | The list index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletCheck | address | The address of a wallet check for the policy. |

### policyWalletChecks

```solidity
function policyWalletChecks(uint32 policyId) external returns (address[] walletChecks)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletChecks | address[] | The list of walletCheck contracts that apply to the policy. |

### isPolicyWalletCheck

```solidity
function isPolicyWalletCheck(uint32 policyId, address walletCheck) external returns (bool isIndeed)
```

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The Policy to inspect. |
| walletCheck | address | The address to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if wallet check applies to the Policy, otherwise false. |

### policyCount

```solidity
function policyCount() public view returns (uint256 count)
```

_Does not check existance._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Existing policies in PolicyManager. |

### isPolicy

```solidity
function isPolicy(uint32 policyId) public view returns (bool isIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if a Policy with policyId exists, otherwise false. |

### globalAttestorCount

```solidity
function globalAttestorCount() external view returns (uint256 count)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Total count of Attestors admitted to the global whitelist. |

### globalAttestorAtIndex

```solidity
function globalAttestorAtIndex(uint256 index) external view returns (address attestor)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | The list index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | An Attestor address from the global whitelist. |

### isGlobalAttestor

```solidity
function isGlobalAttestor(address attestor) public view returns (bool isIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | An address. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the attestor is admitted to the global whitelist. |

### globalWalletCheckCount

```solidity
function globalWalletCheckCount() external view returns (uint256 count)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Total count of wallet checks admitted to the global whitelist. |

### globalWalletCheckAtIndex

```solidity
function globalWalletCheckAtIndex(uint256 index) external view returns (address walletCheck)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | The list index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletCheck | address | A wallet check contract address from the global whitelist. |

### isGlobalWalletCheck

```solidity
function isGlobalWalletCheck(address walletCheck) external view returns (bool isIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletCheck | address | A wallet check contract address to search for. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the wallet check exists in the global whitelist, otherwise false. |

### attestorUri

```solidity
function attestorUri(address attestor) external view returns (string uri)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | An address. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| uri | string | The attestor uri if the address is an attestor. |

### hasRole

```solidity
function hasRole(bytes32 role, address user) public view returns (bool doesIndeed)
```

Inspect user roles.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| role | bytes32 | Access control role to check. |
| user | address | User address to check. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| doesIndeed | bool | True if the user has the role. |

## RuleRegistry

The RuleRegistry holds the global list of all existing Policy rules, which
 can be applied in the PolicyManager contract via the createPolicy and updatePolicy
 functions. Base Rules are managed by the Rule Admin role. Anyone can create an
 expression using an operator and existing Rules as operands.

 Rule toxicity indicates that a rule is deemed to be too precise to use safely on its own
 because doing so would possibly compromise user privacy. Toxicity is inherited by 
 expressions that consume toxic rules. It is not possible to trade where a policy enforces
 toxic rule. 

 An expression that consumes a toxic rule can be declared non-toxic after human review. This
 privilege is reserved for Keyring governance. An expression that is toxic due to inheritance
 can become non-toxic when the expression generalizes the criteria in a way that reduces
 the risks to user privacy, usually by being more inclusive of more qualifying users.

### ROLE_RULE_ADMIN

```solidity
bytes32 ROLE_RULE_ADMIN
```

### constructor

```solidity
constructor(address trustedForwarder) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |

### init

```solidity
function init(string universeDescription, string universeUri, string emptyDescription, string emptyUri) external
```

This upgradeable contract must be initialized.

_Initialiser function MUST be called directly after deployment
     because anyone can call it but overall only once._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| universeDescription | string | Description of the universal set Rule. |
| universeUri | string | The universal set URI. |
| emptyDescription | string | Description of the empty Rule. |
| emptyUri | string | The empty Rule URI. |

### createRule

```solidity
function createRule(string description, string uri, enum IRuleRegistry.Operator operator, bytes32[] operands) public returns (bytes32 ruleId)
```

Anyone can create expressions. Only the Rule Admin can create Base Rules.

_Interpretation of Expressions is deterministic._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| description | string | The description for a Base Rule. Empty for expressions. |
| uri | string | Detailed information Uri for a Base Rule. Empty for expressions. |
| operator | enum IRuleRegistry.Operator | The expression operator (1-3, or Base (0) |
| operands | bytes32[] | The list of the ruleId’s in the expression. Empty for Base Rules. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The unique identifier of the new Rule. Each Policy has exactly one Rule. |

### setToxic

```solidity
function setToxic(bytes32 ruleId, bool toxic) external
```

The rule admin can adjust the toxic flag

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The rule to update |
| toxic | bool | True if the rule is to be set as toxic |

### genesis

```solidity
function genesis() external view returns (bytes32 universeRuleId, bytes32 emptyRuleId)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| universeRuleId | bytes32 | The id of the universal set (everyone) Rule.      @return emptyRuleId The id of the empty (no one) Rule. |
| emptyRuleId | bytes32 |  |

### ruleCount

```solidity
function ruleCount() external view returns (uint256 count)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Number of existing Rules in the global list. |

### ruleAtIndex

```solidity
function ruleAtIndex(uint256 index) external view returns (bytes32 ruleId)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | Iterate rules in the global list. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Id of a rule in the global list. |

### isRule

```solidity
function isRule(bytes32 ruleId) public view returns (bool isIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The unique identifier of a rule. Each Policy has exactly one rule. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True value if Rule exists, otherwise False. |

### rule

```solidity
function rule(bytes32 ruleId) external view returns (string description, string uri, enum IRuleRegistry.Operator operator, uint256 operandCount)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The unique identifier of a rule. Each Policy has exactly one rule. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| description | string | The description for a Base Rule. |
| uri | string | Base Rule uri refers to detailed information about the Rule. |
| operator | enum IRuleRegistry.Operator | The expression operator (0-4), or Base (0) |
| operandCount | uint256 | The number of operands. 0 for Base rules. |

### ruleDescription

```solidity
function ruleDescription(bytes32 ruleId) external view returns (string description)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| description | string | The Rule description. |

### ruleUri

```solidity
function ruleUri(bytes32 ruleId) external view returns (string uri)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| uri | string | The Rule uri. |

### ruleIsToxic

```solidity
function ruleIsToxic(bytes32 ruleId) public view returns (bool isIndeed)
```

Toxic rules can be used in policies without approval

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The rule to inspect |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the rule is toxic |

### ruleOperator

```solidity
function ruleOperator(bytes32 ruleId) external view returns (enum IRuleRegistry.Operator operator)
```

_Does not check existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| operator | enum IRuleRegistry.Operator | The Rule operator. |

### ruleOperandCount

```solidity
function ruleOperandCount(bytes32 ruleId) external view returns (uint256 count)
```

_Does not check Rule existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The number of operands in the Rule expression. |

### ruleOperandAtIndex

```solidity
function ruleOperandAtIndex(bytes32 ruleId, uint256 index) external view returns (bytes32 operandId)
```

_Does not check Rule existance._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The Rule to inspect. |
| index | uint256 | The operand list row to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| operandId | bytes32 | A Rule id. |

### generateRuleId

```solidity
function generateRuleId(string description, enum IRuleRegistry.Operator operator, bytes32[] operands) public pure returns (bytes32 ruleId)
```

Generate a deterministic ruleId

_Warning: This does not validate the inputs_

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The ruleId that will be generated if the configuration is valid |

## KycERC20

This contract illustrates how an immutable KeyringGuard can be wrapped around collateral tokens 
 (e.g. DAI Token). Tokens can only be transferred to an address that maintains compliance with the configured 
 policy.

### constructor

```solidity
constructor(address collateralToken, address keyringCredentials, address policyManager, uint32 policyId, string name_, string symbol_) public
```

Specify the token to wrap and the new name / symbol of the wrapped token - then good to go!
     @param collateralToken The contract address of the token that is to be wrapped
     @param keyringCredentials The address for the deployed KeyringCredentials contract.
     @param policyManager The address for the deployed PolicyManager contract.
     @param policyId The unique identifier of a Policy.
     @param name_ The name of the new wrapped token. Passed to ERC20.constructor to set the ERC20.name
     @param symbol_ The symbol for the new wrapped token. Passed to ERC20.constructor to set the ERC20.symbol

### decimals

```solidity
function decimals() public view returns (uint8)
```

Returns decimals based on the underlying token decimals
     @return uint8 decimals integer

### depositFor

```solidity
function depositFor(address account, uint256 amount) public returns (bool)
```

Compliant users deposit underlying tokens and mint the same number of wrapped tokens.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| account | address | Recipient of the wrapped tokens |
| amount | uint256 | Quantity of underlying tokens from _msgSender() to exchange for wrapped tokens (to account) at 1:1 |

### withdrawTo

```solidity
function withdrawTo(address account, uint256 amount) public returns (bool)
```

Compliant users burn a number of wrapped tokens and withdraw the same number of underlying tokens.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| account | address | Recipient of the underlying tokens |
| amount | uint256 | Quantity of wrapped tokens from _msgSender() to exchange for underlying tokens (to account) at 1:1 |

### transfer

```solidity
function transfer(address to, uint256 amount) public returns (bool)
```

Wraps the inherited ERC20.transfer function with the keyringCompliance guard.
     @param to The recipient of amount 
     @param amount The amount to be deducted from the to's allowance.
     @return bool True if successfully executed.

### transferFrom

```solidity
function transferFrom(address from, address to, uint256 amount) public returns (bool)
```

Wraps the inherited ERC20.transferFrom function with the keyringCompliance guard.
     @param from The sender of amount 
     @param to The recipient of amount 
     @param amount The amount to be deducted from the to's allowance.
     @return bool True if successfully executed.

## WalletCheck

### ROLE_WALLET_CHECK_ADMIN

```solidity
bytes32 ROLE_WALLET_CHECK_ADMIN
```

### isFlagged

```solidity
mapping(address => bool) isFlagged
```

### onlyWalletCheckAdmin

```solidity
modifier onlyWalletCheckAdmin()
```

### constructor

```solidity
constructor(address trustedForwarder) public
```

### setWalletFlag

```solidity
function setWalletFlag(address wallet, bool flagged) external
```

## Pairing

### G1Point

```solidity
struct G1Point {
  uint256 X;
  uint256 Y;
}
```

### G2Point

```solidity
struct G2Point {
  uint256[2] X;
  uint256[2] Y;
}
```

### P1

```solidity
function P1() internal pure returns (struct Pairing.G1Point)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | struct Pairing.G1Point | the generator of G1 |

### P2

```solidity
function P2() internal pure returns (struct Pairing.G2Point)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | struct Pairing.G2Point | the generator of G2 |

### negate

```solidity
function negate(struct Pairing.G1Point p) internal pure returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the negation of p, i.e. p.addition(p.negate()) should be zero. |

### addition

```solidity
function addition(struct Pairing.G1Point p1, struct Pairing.G1Point p2) internal view returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the sum of two points of G1 |

### scalar_mul

```solidity
function scalar_mul(struct Pairing.G1Point p, uint256 s) internal view returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the product of a point on G1 and a scalar, i.e. p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p. |

### pairing

```solidity
function pairing(struct Pairing.G1Point[] p1, struct Pairing.G2Point[] p2) internal view returns (bool)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | the result of computing the pairing check e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1 For example pairing([P1(), P1().negate()], [P2(), P2()]) should return true. |

### pairingProd2

```solidity
function pairingProd2(struct Pairing.G1Point a1, struct Pairing.G2Point a2, struct Pairing.G1Point b1, struct Pairing.G2Point b2) internal view returns (bool)
```

Convenience method for a pairing check for two pairs.

### pairingProd3

```solidity
function pairingProd3(struct Pairing.G1Point a1, struct Pairing.G2Point a2, struct Pairing.G1Point b1, struct Pairing.G2Point b2, struct Pairing.G1Point c1, struct Pairing.G2Point c2) internal view returns (bool)
```

Convenience method for a pairing check for three pairs.

### pairingProd4

```solidity
function pairingProd4(struct Pairing.G1Point a1, struct Pairing.G2Point a2, struct Pairing.G1Point b1, struct Pairing.G2Point b2, struct Pairing.G1Point c1, struct Pairing.G2Point c2, struct Pairing.G1Point d1, struct Pairing.G2Point d2) internal view returns (bool)
```

Convenience method for a pairing check for four pairs.

## Verifier

### VerifyingKey

```solidity
struct VerifyingKey {
  struct Pairing.G1Point alfa1;
  struct Pairing.G2Point beta2;
  struct Pairing.G2Point gamma2;
  struct Pairing.G2Point delta2;
  struct Pairing.G1Point[] IC;
}
```

### Proof

```solidity
struct Proof {
  struct Pairing.G1Point A;
  struct Pairing.G2Point B;
  struct Pairing.G1Point C;
}
```

### verifyingKey

```solidity
function verifyingKey() internal pure returns (struct Verifier.VerifyingKey vk)
```

### verify

```solidity
function verify(uint256[] input, struct Verifier.Proof proof) internal view returns (uint256)
```

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] input) public view returns (bool r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | bool | bool true if proof is valid |

## Pairing

### InvalidProof

```solidity
error InvalidProof()
```

### BASE_MODULUS

```solidity
uint256 BASE_MODULUS
```

### SCALAR_MODULUS

```solidity
uint256 SCALAR_MODULUS
```

### G1Point

```solidity
struct G1Point {
  uint256 X;
  uint256 Y;
}
```

### G2Point

```solidity
struct G2Point {
  uint256[2] X;
  uint256[2] Y;
}
```

### P1

```solidity
function P1() internal pure returns (struct Pairing.G1Point)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | struct Pairing.G1Point | the generator of G1 |

### P2

```solidity
function P2() internal pure returns (struct Pairing.G2Point)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | struct Pairing.G2Point | the generator of G2 |

### negate

```solidity
function negate(struct Pairing.G1Point p) internal pure returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the negation of p, i.e. p.addition(p.negate()) should be zero. |

### addition

```solidity
function addition(struct Pairing.G1Point p1, struct Pairing.G1Point p2) internal view returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the sum of two points of G1 |

### scalar_mul

```solidity
function scalar_mul(struct Pairing.G1Point p, uint256 s) internal view returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the product of a point on G1 and a scalar, i.e. p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p. |

### pairingCheck

```solidity
function pairingCheck(struct Pairing.G1Point[] p1, struct Pairing.G2Point[] p2) internal view
```

Asserts the pairing check
e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
For example pairing([P1(), P1().negate()], [P2(), P2()]) should succeed

## Verifier20

### VerifyingKey

```solidity
struct VerifyingKey {
  struct Pairing.G1Point alfa1;
  struct Pairing.G2Point beta2;
  struct Pairing.G2Point gamma2;
  struct Pairing.G2Point delta2;
  struct Pairing.G1Point[] IC;
}
```

### Proof

```solidity
struct Proof {
  struct Pairing.G1Point A;
  struct Pairing.G2Point B;
  struct Pairing.G1Point C;
}
```

### verifyingKey

```solidity
function verifyingKey() internal pure returns (struct Verifier20.VerifyingKey vk)
```

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[4] input) public view
```

_Verifies a Semaphore proof. Reverts with InvalidProof if the proof is invalid._

## IKeyringECRecoverTyped

### getSignerFromSig

```solidity
function getSignerFromSig(address user, uint32 userPolicyId, uint32 admissionPolicyId, uint256 timestamp, bool isRequest, bytes signature) external view returns (address signer)
```

### getHashFromAttestation

```solidity
function getHashFromAttestation(address user, uint32 userPolicyId, uint32 admissionPolicyId, uint256 timestamp, bool isRequest) external view returns (bytes32 message)
```

## NoImplementation

This stub provides a hint for hardhat artifacts and typings. It is a non-functional
 implementation to deploy behind a TransparentUpgradeableProxy. The proxy address will be passed
 to constructors that expect an immutable trusted forwarder for future gasless transaction
 support (trustedForwarder). This contract implements the essential functions as stubs that
 fail harmlessly.

### ForwardRequest

```solidity
struct ForwardRequest {
  address from;
  address to;
  uint256 value;
  uint256 gas;
  uint256 nonce;
  bytes data;
}
```

### NotImplemented

```solidity
error NotImplemented(address sender, string message)
```

### getNonce

```solidity
function getNonce(address) public pure returns (uint256)
```

### verify

```solidity
function verify(struct NoImplementation.ForwardRequest, bytes) public pure returns (bool)
```

### execute

```solidity
function execute(struct NoImplementation.ForwardRequest, bytes) public payable returns (bool, bytes)
```

## Pairing

### G1Point

```solidity
struct G1Point {
  uint256 X;
  uint256 Y;
}
```

### G2Point

```solidity
struct G2Point {
  uint256[2] X;
  uint256[2] Y;
}
```

### P1

```solidity
function P1() internal pure returns (struct Pairing.G1Point)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | struct Pairing.G1Point | the generator of G1 |

### P2

```solidity
function P2() internal pure returns (struct Pairing.G2Point)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | struct Pairing.G2Point | the generator of G2 |

### negate

```solidity
function negate(struct Pairing.G1Point p) internal pure returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the negation of p, i.e. p.addition(p.negate()) should be zero. |

### addition

```solidity
function addition(struct Pairing.G1Point p1, struct Pairing.G1Point p2) internal view returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the sum of two points of G1 |

### scalar_mul

```solidity
function scalar_mul(struct Pairing.G1Point p, uint256 s) internal view returns (struct Pairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct Pairing.G1Point | the product of a point on G1 and a scalar, i.e. p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p. |

### pairing

```solidity
function pairing(struct Pairing.G1Point[] p1, struct Pairing.G2Point[] p2) internal view returns (bool)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | the result of computing the pairing check e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1 For example pairing([P1(), P1().negate()], [P2(), P2()]) should return true. |

### pairingProd2

```solidity
function pairingProd2(struct Pairing.G1Point a1, struct Pairing.G2Point a2, struct Pairing.G1Point b1, struct Pairing.G2Point b2) internal view returns (bool)
```

Convenience method for a pairing check for two pairs.

### pairingProd3

```solidity
function pairingProd3(struct Pairing.G1Point a1, struct Pairing.G2Point a2, struct Pairing.G1Point b1, struct Pairing.G2Point b2, struct Pairing.G1Point c1, struct Pairing.G2Point c2) internal view returns (bool)
```

Convenience method for a pairing check for three pairs.

### pairingProd4

```solidity
function pairingProd4(struct Pairing.G1Point a1, struct Pairing.G2Point a2, struct Pairing.G1Point b1, struct Pairing.G2Point b2, struct Pairing.G1Point c1, struct Pairing.G2Point c2, struct Pairing.G1Point d1, struct Pairing.G2Point d2) internal view returns (bool)
```

Convenience method for a pairing check for four pairs.

## Verifier

### VerifyingKey

```solidity
struct VerifyingKey {
  struct Pairing.G1Point alfa1;
  struct Pairing.G2Point beta2;
  struct Pairing.G2Point gamma2;
  struct Pairing.G2Point delta2;
  struct Pairing.G1Point[] IC;
}
```

### Proof

```solidity
struct Proof {
  struct Pairing.G1Point A;
  struct Pairing.G2Point B;
  struct Pairing.G1Point C;
}
```

### verifyingKey

```solidity
function verifyingKey() internal pure returns (struct Verifier.VerifyingKey vk)
```

### verify

```solidity
function verify(uint256[] input, struct Verifier.Proof proof) internal view returns (uint256)
```

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[5] input) public view returns (bool r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | bool | bool true if proof is valid |
