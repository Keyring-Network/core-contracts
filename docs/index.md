# Solidity API

## KeyringAccessControl

This contract manages the role-based access control via _checkRole() with meaningful 
error messages if the user does not have the requested role. This Contract is inherited by the 
PolicyManager, RuleRegistry, KeyringCredentials and KeyringCredentialUpdater contract.

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

Role-based access control

_Revert if account is missing role_

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| role | bytes32 | Verify the account has this role |
| account | address | A DeFi address to check for the role |
| context | string | The function that requested the permission check |

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

Returns msg.data if not from a trusted forwarder,
or truncated msg.data if the signer was appended to msg.data

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bytes | data Data deemed to be the msg.data |

## KeyringZkCredentialUpdater

This contract acts as a Credentials Updater, which needs to have ROLE_CREDENTIAL_UPDATER 
 permission in the KeyringCredentials contract in order to record Credentials. The contract checks 
 signatures via the getSignerFromSig function and therefore enforces the protocol.

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

### identityTreeSet

```solidity
struct AddressSet.Set identityTreeSet
```

### onlyIdentityTreeAdmin

```solidity
modifier onlyIdentityTreeAdmin()
```

### constructor

```solidity
constructor(address trustedForwarder, address keyringCredentials, address policyManager, address keyringZkVerifier) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| keyringCredentials | address | The address for the deployed {KeyringCredentials} contract. |
| policyManager | address | The address for the deployed PolicyManager contract. |
| keyringZkVerifier | address |  |

### admitIdentityTree

```solidity
function admitIdentityTree(address identityTree) external
```

The identityTree admin can authorize identity tree instances.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| identityTree | address | The address of a contract supporting the IIdentityTree interface. |

### removeIdentityTree

```solidity
function removeIdentityTree(address identityTree) external
```

The identityTree admin can unauthorize identity tree instances.

### updateCredentials

```solidity
function updateCredentials(address identityTree, struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorizationProof) external
```

Updates the credential cache if the request is acceptable.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| identityTree | address | The contract with a root a tree that contains the hash of identity + userPolicy hash. |
| membershipProof | struct IKeyringZkVerifier.IdentityMembershipProof | The zero-knowledge proof of membership in the tree. |
| authorizationProof | struct IKeyringZkVerifier.IdentityAuthorisationProof | The zero-knowledge of compliance with up to 24 policy disclosures. |

### checkPolicyAndWallet

```solidity
function checkPolicyAndWallet(address trader, uint32 policyId, address identityTree) public returns (bool acceptable)
```

Check identity tree, policy and trader wallet.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The trader wallet to inspect. |
| policyId | uint32 | The policy to inspect. |
| identityTree | address | The identity tree contract address to compare to the policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| acceptable | bool | True if the policy rule is innocuous, the tree is authoritative and the wallet is not flagged. |

## KeyringECRecoverTyped

This contract is inherited by the KeyringCredentialUpdater contract, in order to retrieve 
 the address of a signer from a signature via the getSignerFromSig function. Messages are signed 
 according to the EIP-712 standard for hashing and signing of typed structured data.

### constructor

```solidity
constructor() internal
```

Generate the EIP712 Type Hash for Keyring attestations.

### getSignerFromSig

```solidity
function getSignerFromSig(address user, uint32 userPolicyId, uint32 admissionPolicyId, uint256 timestamp, bool isRequest, bytes signature) public view returns (address signer)
```

Ecrecover the signer from the full signature of a Keyring attestation.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The User address for the Credentials update. |
| userPolicyId | uint32 | The unique identifier of the user Policy currently assigned. |
| admissionPolicyId | uint32 | The unique identifier of a Policy. |
| timestamp | uint256 | EVM time of the Attestation. |
| isRequest | bool | True if the User is requesting, False if a Verifier is signing. |
| signature | bytes | The full signature. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| signer | address | The elliptic curve recovered address. |

### getHashFromAttestation

```solidity
function getHashFromAttestation(address user, uint32 userPolicyId, uint32 admissionPolicyId, uint256 timestamp, bool isRequest) public view returns (bytes32 messageHash)
```

Generate the EIP712 message hash for a Keyring attestation.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The User address for the Credentials update. |
| userPolicyId | uint32 | The unique identifier of the user Policy currently assigned. |
| admissionPolicyId | uint32 | The unique identifier of a Policy to compare. |
| timestamp | uint256 | EVM time of the Attestation. |
| isRequest | bool | True if the User is requesting, False if a Verifier is signing. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| messageHash | bytes32 | The EIP712 message hash. |

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

## IdentyTree

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

### setMerkleRootBirthday

```solidity
function setMerkleRootBirthday(bytes32 merkleRoot, uint256 birthday) external
```

The aggretator can set roots with non-zero birthdays.

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

Check for existence in history. Ignore purged entries.

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

### garbageCollection

```solidity
function garbageCollection() internal
```

This special delete function nullifies stored roots without re-ordering the set or reducing the count.

## KeyringGuardV1

Adds Keyring compliance support to derived contracts.

_Add the modifier to functions to protect._

### Compliance

```solidity
error Compliance(address sender, address user, string module, string method, string reason)
```

### checkKeyring

```solidity
modifier checkKeyring(address user, address keyringCredentials, address policyManager, uint32 admissionPolicyId, bytes32 universeRule, bytes32 emptyRule)
```

_Use this flexible modifier to enforce distinct policies on functions within the same contract._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The User address for the Credentials update. |
| keyringCredentials | address | The address for the deployed KeyringCredentials contract. |
| policyManager | address | The address for the deployed PolicyManager contract. |
| admissionPolicyId | uint32 | The unique identifier of a Policy. |
| universeRule | bytes32 | The id of the universe (everyone) Rule. |
| emptyRule | bytes32 | The id of the empty (noone) Rule. |

### _isCompliant

```solidity
function _isCompliant(address user, address keyringCredentials, address policyManager, uint32 admissionPolicyId, bytes32 universeRule, bytes32 emptyRule) internal returns (bool isIndeed)
```

Checks if the given user is Keyring Compliant.

_Use static call to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The User address for the Credentials update. |
| keyringCredentials | address | The address for the deployed KeyringCredentials contract. |
| policyManager | address | The address for the deployed PolicyManager contract. |
| admissionPolicyId | uint32 | The unique identifier of a Policy. |
| universeRule | bytes32 | The id of the universe (everyone) Rule. |
| emptyRule | bytes32 | The id of the empty (noone) Rule. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if a valid credential is found, |

## KeyringGuardV1Immutable

KeyringGuard implementation that uses immutables and presents a simplified modifier.

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

_Use this modifier to enforce distinct Policies on functions within the same contract._

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
| policyManager | address | The address for the deployed PolicyManager contract. |
| admissionPolicyId | uint32 | The unique identifier of a Policy. |

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
| emptyRuleId | bytes32 | The id of the empty set Rule (no one), |

### checkKeyringCompliance

```solidity
function checkKeyringCompliance(address user) external returns (bool isCompliant)
```

Checks user compliance status,

_Use static call to inspect,_

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | User to check |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isCompliant | bool | true if the user can proceed, |

### _isPolicy

```solidity
function _isPolicy(address policyManager, uint32 policyId) internal view returns (bool isIndeed)
```

Checks the existence of policyId in the PolicyManager contract.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyManager | address | The address for the deployed PolicyManager contract. |
| policyId | uint32 | The unique identifier of a Policy. |

## IAuthorizationProofVerifier

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[7] input) external view returns (bool)
```

## IIdentityConstructionProofVerifier

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[4] input) external view returns (bool r)
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
error Unacceptable(address sender, string module, string method, string reason)
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
error Unacceptable(address sender, string module, string method, string reason)
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

## IKeyringECRecoverTyped

### getSignerFromSig

```solidity
function getSignerFromSig(address user, uint32 userPolicyId, uint32 admissionPolicyId, uint256 timestamp, bool isRequest, bytes signature) external view returns (address signer)
```

### getHashFromAttestation

```solidity
function getHashFromAttestation(address user, uint32 userPolicyId, uint32 admissionPolicyId, uint256 timestamp, bool isRequest) external view returns (bytes32 message)
```

## IKeyringGuardV1Immutable

KeyringGuard implementation that uses immutables and presents a simplified modifier.

### Unacceptable

```solidity
error Unacceptable(address sender, string module, string method, string reason)
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

### Rejected

```solidity
error Rejected(address sender, address trader, string module, string method, uint32 policyId, string reason)
```

### ProofFailure

```solidity
error ProofFailure(address sender, address trader, string module, string method, string reason)
```

### Unacceptable

```solidity
error Unacceptable(address sender, string module, string method, string reason)
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
function updateCredentials(address identityTree, struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorizationProof) external
```

### checkPolicyAndWallet

```solidity
function checkPolicyAndWallet(address trader, uint32 policyId, address identityTree) external returns (bool acceptable)
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
  uint256 version;
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
  uint256 externalNullifier;
  uint256 signalHash;
}
```

### IdentityAuthorisationProof

```solidity
struct IdentityAuthorisationProof {
  struct IKeyringZkVerifier.Groth16Proof proof;
  uint256[2] versionRange;
  uint256 externalNullifier;
  uint256 nullifierHash;
  uint256[2] policyDisclosures;
  address tradingAddress;
}
```

### checkClaim

```solidity
function checkClaim(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof, address trader) external view returns (bool verified)
```

### checkIdentityConstructionProof

```solidity
function checkIdentityConstructionProof(struct IKeyringZkVerifier.IdentityConstructionProof constructionProof, uint256 maxAddresses) external view returns (bool verified)
```

### checkIdentityMembershipProof

```solidity
function checkIdentityMembershipProof(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof) external view returns (bool verified)
```

### checkIdentityAuthorisationProof

```solidity
function checkIdentityAuthorisationProof(struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof, address sender) external view returns (bool verified)
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
error Unacceptable(address sender, string module, string method, string reason)
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

### GlobalMinimumGracePeriod

```solidity
event GlobalMinimumGracePeriod(address admin, uint32 minimumGracePeriod)
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

### ROLE_GLOBAL_GRACE_ADMIN

```solidity
function ROLE_GLOBAL_GRACE_ADMIN() external view returns (bytes32)
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

### setGlobalGraceTime

```solidity
function setGlobalGraceTime(uint32 minimumGracePeriod) external
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

### globalMinimumGracePeriod

```solidity
function globalMinimumGracePeriod() external view returns (uint256 gracePeriod)
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
  bool innocuous;
}
```

### Unacceptable

```solidity
error Unacceptable(address sender, string module, string method, string reason)
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
event CreateRule(address user, bytes32 ruleId, string description, string uri, bool innocuous, enum IRuleRegistry.Operator operator, bytes32[] operands)
```

### SetInnocuous

```solidity
event SetInnocuous(address admin, bytes32 ruleId, bool isInnocuous)
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

### setInnocuous

```solidity
function setInnocuous(bytes32 ruleId, bool innocuous) external
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

### ruleIsInnocuous

```solidity
function ruleIsInnocuous(bytes32 ruleId) external view returns (bool isIndeed)
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

### roleRuleAdmin

```solidity
function roleRuleAdmin() external pure returns (bytes32 role)
```

## IWalletCheck

### Unacceptable

```solidity
error Unacceptable(address sender, string module, string method, string reason)
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

The KeyringCredentials holds credentials organized by user and policy. 
 The credentials are non-transferrable and are represented as timestamps. Non-zero 
 entries indicate that the required number of Verifiers signed an attestion to
 indicated that the policies are compatible and the user is compatible with 
 the policies.

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

### cache

```solidity
mapping(uint8 => mapping(address => mapping(uint32 => mapping(uint256 => uint256)))) cache
```

(version => trader => admissionPolicyId) => epoch => updateTime

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
     @dev Initializer function MUST be called directly after deployment 
     because anyone can call it but overall only once.

### tearDownAdmissionPolicyCredentials

```solidity
function tearDownAdmissionPolicyCredentials(uint32 policyId) external
```

The policy admin can force all users to refresh their cache immediately

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy with credentials to tear down |

### setCredential

```solidity
function setCredential(address trader, uint32 admissionPolicyId, uint256 timestamp) external
```

This function is usually executed by a trusted and permitted contract.
     @param trader The user address for the Credential update.
     @param admissionPolicyId The unique identifier of a Policy.
     @param timestamp The timestamp established when the user requested a credential.

### getCredential

```solidity
function getCredential(uint8 version, address trader, uint32 admissionPolicyId) external view returns (uint256 timestamp)
```

This function is usually executed by a trusted and permitted contract.
     @param version Cache organization version.
     @param trader The user to inspect.
     @param admissionPolicyId The admission policy for the credential to inspect.
     @return timestamp The timestamp established when the user refreshed the credential.

## KeyringVerifier

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
function checkClaim(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof, address trader) external view returns (bool verified)
```

Check identity construction, membership and authorization.
     @param membershipProof Proof of inclusion in an identity tree.
     @param authorisationProof Proof of policyId inclusions in the identity commitment.
     @return verified True if the claim is valid.

### checkIdentityConstructionProof

```solidity
function checkIdentityConstructionProof(struct IKeyringZkVerifier.IdentityConstructionProof constructionProof, uint256 maxAddresses) external view returns (bool verified)
```

Check correct construction of an identity commitment.
     @param constructionProof Proof of correct construction of the identity commitment.
     @param maxAddresses The maximum addresses included in the identity commitment.
     @return verified True if the proof is valid.

### checkIdentityMembershipProof

```solidity
function checkIdentityMembershipProof(struct IKeyringZkVerifier.IdentityMembershipProof membershipProof) public view returns (bool verified)
```

Check that the identity commitment is a member of the identity tree.
     @param membershipProof Proof of membership.
     @return verified True if the identity commitment is a member of the identity tree.

### checkIdentityAuthorisationProof

```solidity
function checkIdentityAuthorisationProof(struct IKeyringZkVerifier.IdentityAuthorisationProof authorisationProof, address sender) public view returns (bool verified)
```

Check if the policies disclosed are included in the identity commitment.
     @param authorisationProof Proof of authorisation.
     @param sender The trader wallet to authorise.
     @return verified True if the trader wallet is authorised for all policies in the disclosure.

## AddressSet

Key sets with enumeration and delete. Uses mappings for random and existence checks
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
| self | struct AddressSet.Set | A Address32Set struct - similar syntax to python classes. |
| key | address | A key to the Address32Set. |
| context | string | A message string about interpretation of the issue. |

### remove

```solidity
function remove(struct AddressSet.Set self, address key, string context) internal
```

Remove a key from the store.

_key to remove must exist._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Address32Set struct - similar syntax to python classes. |
| key | address | A key to the Address32Set. |
| context | string | A message string about interpretation of the issue. |

### count

```solidity
function count(struct AddressSet.Set self) internal view returns (uint256)
```

Count the keys.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Address32Set struct - similar syntax to python classes. |

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
| self | struct AddressSet.Set | A Address32Set struct - similar syntax to python classes |
| key | address | A key to the Address32Set. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool True if key exists in the Set, otherwise false. |

### keyAtIndex

```solidity
function keyAtIndex(struct AddressSet.Set self, uint256 index) internal view returns (address)
```

Retrieve an address by its key.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct AddressSet.Set | A Address32Set struct - similar syntax to python classes. |
| index | uint256 | The internal index of the keys |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | address | address Address value stored in a `keyList`. |

## Bytes32Set

Key sets with enumeration. Uses mappings for random and existence checks
and dynamic arrays for enumeration. Key uniqueness is enforced.

_Sets are unordered._

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
| self | struct Bytes32Set.Set | A Bytes32Set struct - similar syntax to python classes. |
| key | bytes32 | A value in the Bytes32Set. |
| context | string | A message string about interpretation of the issue. |

### count

```solidity
function count(struct Bytes32Set.Set self) internal view returns (uint256)
```

Count the keys.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Bytes32Set struct - similar syntax to python classes. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | uint256 | uint256 Length of the `keyList`, which correspond to the number of elements stored in the `keyPointers` mapping. |

### exists

```solidity
function exists(struct Bytes32Set.Set self, bytes32 key) internal view returns (bool)
```

Check if a key exists in the Set.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Bytes32Set struct - similar syntax to python classes. |
| key | bytes32 | A value in the Bytes32Set. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool True if key exists in the Set, otherwise false. |

### keyAtIndex

```solidity
function keyAtIndex(struct Bytes32Set.Set self, uint256 index) internal view returns (bytes32)
```

Retrieve an bytes32 by its key.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Bytes32Set struct - similar syntax to python classes. |
| index | uint256 | The internal index of the keys |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bytes32 | bytes32 The bytes32 value stored in a `keyList`. |

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
     @dev uint32 Inputs are truncated after 20 bits.
     @param input Array of integers to pack.

### unpack

```solidity
function unpack(uint256 packed) public pure returns (uint32[12] output)
```

Unpack 12 20-bit integers from 240-bit input
     @dev Packed input is truncated after 240 bits.
     @param packed 12 20-bit integers packed into 240 bits.
     @return output 12 20-bit integers cast as 32-bit integers.

## Pack12x20

### pack12x20

```solidity
function pack12x20(uint32[12] input) public pure returns (uint256 packed)
```

### unpack12x20

```solidity
function unpack12x20(uint256 packed) public pure returns (uint32[12] unpacked)
```

## PolicyStorage

### Rejected

```solidity
error Rejected(string reason)
```

### App

```solidity
struct App {
  uint32 minimumGracePeriod;
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

### insertGlobalWalletCheck

```solidity
function insertGlobalWalletCheck(struct PolicyStorage.App self, address walletCheck) public
```

### removeGlobalWalletCheck

```solidity
function removeGlobalWalletCheck(struct PolicyStorage.App self, address walletCheck) public
```

### removeGlobalAttestor

```solidity
function removeGlobalAttestor(struct PolicyStorage.App self, address attestor) public
```

### setMinimumGracePeriod

```solidity
function setMinimumGracePeriod(struct PolicyStorage.App self, uint32 minimumGracePeriod) public
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

### checkPolicyExists

```solidity
function checkPolicyExists(struct PolicyStorage.App self, uint32 policyId) public view
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
function writeGracePeriod(struct PolicyStorage.Policy self, uint32 gracePeriod, uint32 minimumGracePeriod) public
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

## PolicyManager

PolicyManager holds the policies managed by DeFi Protocol Operators and users. 
 When used by a KeyringGuard, policies describe admission rules that will be enforced. 
 When used by a Trader, policies describe the rules that compliant DeFi Protocol Operators 
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

### ROLE_GLOBAL_GRACE_ADMIN

```solidity
bytes32 ROLE_GLOBAL_GRACE_ADMIN
```

### ruleRegistry

```solidity
address ruleRegistry
```

### policyStorage

```solidity
struct PolicyStorage.App policyStorage
```

### Rejected

```solidity
error Rejected(string reason)
```

### onlyPolicyAdmin

```solidity
modifier onlyPolicyAdmin(uint32 policyId)
```

Policy admin role is initially granted during createPolicy.

_Revert if the msg sender doesn't have the policy admin role._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |

### onlyPolicyCreator

```solidity
modifier onlyPolicyCreator()
```

Keyring Governance has exclusive access to the global whitelist of Attestors.

_Revert if the user doesn't have the global attestor admin role._

### onlyAttestorAdmin

```solidity
modifier onlyAttestorAdmin()
```

Keyring Governance has exclusive access to the global whitelist of Attestors.

_Revert if the user doesn't have the global attestor admin role._

### onlyWalletCheckAdmin

```solidity
modifier onlyWalletCheckAdmin()
```

Keyring Governance has exclusive access to the global whitelist of Wallet Checks.

_Revert if the user doesn't have the global attestor admin role._

### onlyGraceAdmin

```solidity
modifier onlyGraceAdmin()
```

Keyring Governance has exclusive access to the global whitelist of Attestors.

_Revert if the user doesn't have the global attestor admin role._

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

Anyone can create an admission Policy and is granted admin and user admin.

_`requiredAttestors` is never higher than the number of Attestors in the Policy._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyScalar | struct PolicyStorage.PolicyScalar | The policy object scalar values. |
| attestors | address[] | Acceptable attestors. |
| walletChecks | address[] | Policy wallet checks. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a Policy. |
| policyOwnerRoleId | bytes32 |  |
| policyUserAdminRoleId | bytes32 |  |

### updatePolicyScalar

```solidity
function updatePolicyScalar(uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, uint256 deadline) external
```

The Policy admin role can update the parameters.

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

Policy admins can force acceptance of the last n identity tree roots.

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

Each user sets exactly one Policy to compare with admission policies.

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
| uri | string | The URI points to detailed information about the attestor. |

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
| attestor | address | The address of a Attestor on the global whitelist. |

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

### setGlobalGraceTime

```solidity
function setGlobalGraceTime(uint32 minimumGracePeriod) external
```

The global grace admin can set the minimum acceptable policy grace period.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| minimumGracePeriod | uint32 | The lowest allowable policy grace period. |

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
| config | struct PolicyStorage.PolicyScalar | The configuration of the policy. |
| attestors | address[] | The authorized attestors for the policy. |
| walletChecks | address[] | The policy wallet checks. |
| deadline | uint256 | The timestamp when staged changes will take effect. |

### policyRawData

```solidity
function policyRawData(uint32 policyId) external view returns (uint256 deadline, struct PolicyStorage.PolicyScalar scalarActive, struct PolicyStorage.PolicyScalar scalarPending, address[] attestorsActive, address[] attestorsPendingAdditions, address[] attestorsPendingRemovals, address[] walletChecksActive, address[] walletChecksPendingAdditions, address[] walletChecksPendingRemovals)
```

Reveals the internal state of the policy object without processing staged changes.

_non-zero deadline in the past indicated staged object is in effect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

### policyOwnerRole

```solidity
function policyOwnerRole(uint32 policyId) public pure returns (bytes32 ownerRole)
```

Generate corresponding admin role for a policyId

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
| ruleId | bytes32 | Enforced Rule from RuleRegistry. |

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
| acceptRoots | uint16 | The number of latest identity roots to accept unconditionally. |

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
| isIndeed | bool | True if attestor is acceptable for the Policy, otherwise false. |

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
| isIndeed | bool | True if Policy with policyId exists, otherwise false. |

### globalMinimumGracePeriod

```solidity
function globalMinimumGracePeriod() external view returns (uint256 minimumGracePeriod)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| minimumGracePeriod | uint256 | The global minimum grace period. |

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
| attestor | address | A Attestor address from the global whitelist. |

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
| uri | string | The uri if the address is an attestor. |

### hasRole

```solidity
function hasRole(bytes32 role, address user) public view returns (bool doesIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| role | bytes32 | Access control role to check. |
| user | address | Address to check. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| doesIndeed | bool | True if the user has the role. |

## RuleRegistry

The RuleRegistry holds the global list of all existing Policy rules, which
can be applied in the PolicyManager contract via the createPolicy and updatePolicy
functions. Base Rules are managed by  the Rule Admin role. Anyone can create an
expression using an operator and existing Rules as operands.

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
| ruleId | bytes32 | The unique identifier of Rule. Each Policy has exactly one Rule. |

### setInnocuous

```solidity
function setInnocuous(bytes32 ruleId, bool innocuous) external
```

The rule admin can adjust the innocuous flag

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The rule to update |
| innocuous | bool | True if the rule is to be set as innocuous |

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

### ruleIsInnocuous

```solidity
function ruleIsInnocuous(bytes32 ruleId) public view returns (bool isIndeed)
```

Innocuous rules can be used in policies without approval

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The rule to inspect |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the rule is innocuous |

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

### roleRuleAdmin

```solidity
function roleRuleAdmin() external pure returns (bytes32 role)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| role | bytes32 | The constant ROLE_RULE_ADMIN |

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

## NoImplementation

This stub provides a hint for hardhat artifacts and typings. It is a non-functional
implementation to deploy behind a TransparentUpgradeableProxy which address will be passed
to constructors that expect an immutable address to trust for future gasless transaction
support (trustedForwarder).

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
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[4] input) public view returns (bool r)
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
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[7] input) public view returns (bool r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | bool | bool true if proof is valid |

