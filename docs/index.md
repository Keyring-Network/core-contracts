# Solidity API

## KeyringAccessControl

This contract manages the role-based access control via _checkRole() with meaningful 
 error messages if the user does not have the requested role. This contract is inherited by 
 PolicyManager, RuleRegistry, KeyringCredentials, IdentityTree, WalletCheck and 
 KeyringZkCredentialUpdater.

### Unacceptable

```solidity
error Unacceptable(string reason)
```

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

### supportsInterface

```solidity
function supportsInterface(bytes4) public view virtual returns (bool)
```

Disables incomplete ERC165 support inherited from oz/AccessControl.sol

_Always reverts. Do not rely on ERC165 support to interact with this contract._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool Never returned. |

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

## Consent

### maximumConsentPeriod

```solidity
uint256 maximumConsentPeriod
```

### userConsentDeadlines

```solidity
mapping(address => uint256) userConsentDeadlines
```

_Mapping of Traders to their associated consent deadlines._

### constructor

```solidity
constructor(address trustedForwarder, uint256 maximumConsentPeriod_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | The address of a trustedForwarder contract. |
| maximumConsentPeriod_ | uint256 | The upper limit for user consent deadlines. |

### grantDegradedServiceConsent

```solidity
function grantDegradedServiceConsent(uint256 revocationDeadline) external
```

A user may grant consent to service mitigation measures.

_The deadline must be no further in the future than the maximumConsentDeadline._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| revocationDeadline | uint256 | The consent will automatically expire at the deadline. |

### revokeMitigationConsent

```solidity
function revokeMitigationConsent() external
```

A user may revoke their consent to mitigation measures.

### userConsentsToMitigation

```solidity
function userConsentsToMitigation(address user) public view returns (bool doesIndeed)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | address | The user to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| doesIndeed | bool | True if the user's consent deadline is in the future. |

## KeyringZkCredentialUpdater

This contract acts as a credentials cache updater. It needs the ROLE_CREDENTIAL_UPDATER 
 permission in the KeyringCredentials contract in order to record credentials. The contract checks 
 client-generated zero-knowledge proofs of attestations about admission policy eligibility and 
 therefore enforces the protocol.

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
     to the system globally before it was selected for a policy. The two zero-knowledge proof share parameters that 
     ensure that both proofs were derived from the same identity commitment. If the root age used to construct proofs
     if older than the policy time to live (ttl), the root will be considered acceptable with an age of zero, provided
     that the number of root successors is less than or equal to the policy acceptRoots (accept most recent n roots)._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attestor | address | The identityTree contract with a root that contains the user's identity commitment. Must be       present in the current attestor list for all policy disclosures in the authorization proof. |
| membershipProof | struct IKeyringZkVerifier.IdentityMembershipProof | A zero-knowledge proof of identity commitment membership in the identity tree. Contains an      external nullifier and nullifier hash that must match the parameters of the authorization proof. |
| authorizationProof | struct IKeyringZkVerifier.IdentityAuthorisationProof | A zero-knowledge proof of compliance with up to 24 policy disclosures. Contains an      external nullifier and nullifier hash that must match the parameters of the membershiip proof. |

### checkPolicy

```solidity
function checkPolicy(uint32 policyId, address attestor) public returns (bool acceptable)
```

The identity tree must be a policy attestor and the policy rule cannot be toxic.

_Use static call to inspect response._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |
| attestor | address | The identity tree contract address to compare to the policy attestors. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| acceptable | bool | True if the policy rule is not toxic and the identity tree is authoritative for the policy. |

### pack12x20

```solidity
function pack12x20(uint32[12] input) public pure returns (uint256 packed)
```

Packs uint32[12] into uint256 with 20-bit precision.

_uint32 Inputs are limited to 20 bits of magnitude._

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

## Degradable

_A contract that allows services to specify how to mitigate service interuptions
using policy-specific parameters._

### ROLE_SERVICE_SUPERVISOR

```solidity
bytes32 ROLE_SERVICE_SUPERVISOR
```

### defaultDegradationPeriod

```solidity
uint256 defaultDegradationPeriod
```

### defaultFreshnessPeriod

```solidity
uint256 defaultFreshnessPeriod
```

### policyManager

```solidity
address policyManager
```

### lastUpdate

```solidity
uint256 lastUpdate
```

### subjectUpdates

```solidity
mapping(bytes32 => uint256) subjectUpdates
```

_Mapping of storage subjects to their associated update timestamps._

### onlyPolicyAdminOrSupervisor

```solidity
modifier onlyPolicyAdminOrSupervisor(uint32 policyId)
```

_Modifier that checks if the caller has the policy admin or supervisor role._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy. |

### constructor

```solidity
constructor(address trustedForwarder, address policyManager_, uint256 maximumConsentPeriod_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Address of the trusted forwarder contract. |
| policyManager_ | address | Address of the policy manager contract. |
| maximumConsentPeriod_ | uint256 | Maximum consent duration a user will be allowed to grant. |

### _recordUpdate

```solidity
function _recordUpdate(address subject, uint256 time) internal
```

Record the timestamp of the last update to the contract.

_Must be called by derived contracts._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| subject | address | The subject to update. |
| time | uint256 | The time to record. |

### _recordUpdate

```solidity
function _recordUpdate(bytes32 subject, uint256 time) internal
```

Record the timestamp of the last update to the contract.

_Must be called by derived contracts._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| subject | bytes32 | The subject to update. |
| time | uint256 | The time to record. |

### setPolicyParameters

```solidity
function setPolicyParameters(uint32 policyId, uint256 degradationPeriod_, uint256 degradationFreshness_) external
```

_Set the mitigation parameters for a policy._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy. |
| degradationPeriod_ | uint256 | The time period after which the service is considered degraded. |
| degradationFreshness_ | uint256 | Used by derived service contracts to include or exclude data that was recorded before the service fell into the degraded state. |

### _checkKey

```solidity
function _checkKey(address observer, address subject, uint32 policyId) internal returns (bool pass)
```

Check the subjects's last recorded update and compare to policy ttl, with mitigation.

_Fallback to mitigation measures if acceptable. Use staticCall to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The user who must consent to reliance on degraded services. |
| subject | address | The subject to inspect. |
| policyId | uint32 | PolicyId to consider for possible mitigation. |

### _checkKey

```solidity
function _checkKey(address observer, bytes32 subject, uint32 policyId) internal returns (bool pass)
```

Check the subject's last recorded update and compare to policy ttl, with mitigation.

_Fallback to mitigation measures if acceptable. Use staticCall to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The user who must consent to reliance on degraded services. |
| subject | bytes32 | The subject to inspect. |
| policyId | uint32 | PolicyId to consider for possible mitigation. |

### canMitigate

```solidity
function canMitigate(address observer, bytes32 subject, uint32 policyId) public view virtual returns (bool canIndeed)
```

A Degradable service implments a compromised process.

_Must consult user Consent and Policy parameters. Must return false unless degraded.
Use staticCall to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The user who must consent to reliance on degraded services. |
| subject | bytes32 | The topic to inspect. |
| policyId | uint32 | The policyId for mitigation parameters. |

### _canMitigate

```solidity
function _canMitigate(address observer, uint32 policyId, uint256 time, uint256 subjectUpdated) internal view returns (bool canIndeed)
```

A Degradable service implments a compromised process.

_Must consult user Consent and Policy parameters. Must return false unless degraded._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The user who must consent to reliance on degraded services. |
| policyId | uint32 | The policyId for mitigation parameters. |
| time | uint256 | Derived contracts and callers provide current blocktime for comparison. |
| subjectUpdated | uint256 | Derived contracts and callers provide last subject update. |

### isDegraded

```solidity
function isDegraded(uint32 policyId) public view returns (bool isIndeed)
```

A service is degraded if there has been no update for longer than the degradation period.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the service is considered degraded by the Policy. |

### _isDegraded

```solidity
function _isDegraded(uint32 policyId, uint256 time) internal view returns (bool isIndeed)
```

A service is degraded if there has been no update for longer than the degradation period.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to inspect. |
| time | uint256 | Time to compare. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the service is considered degraded by the Policy. |

### isMitigationQualified

```solidity
function isMitigationQualified(bytes32 subject, uint32 policyId) public view returns (bool qualifies)
```

Evaluate if existing services records can be used for mitigation measures.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| subject | bytes32 | Key to inspect. |
| policyId | uint32 | Policy to inspect for mitigation parameters. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| qualifies | bool | True if the birthday is after the cutoff deadline for the service set by the Policy admin. |

### _isMitigationQualified

```solidity
function _isMitigationQualified(uint256 lastSubjectUpdate, uint32 policyId) internal view returns (bool qualifies)
```

Evaluate if existing services records can be used for mitigation measures.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| lastSubjectUpdate | uint256 | Last recorded update for the subject. |
| policyId | uint32 | Policy to inspect for mitigation parameters. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| qualifies | bool | True if the subject update time is after the mitigation cutoff  for the service set by the Policy admin. |

### degradationPeriod

```solidity
function degradationPeriod(uint32 policyId) public view returns (uint256 inSeconds)
```

The degradation period is maximum interval between updates before the policy considers the
service degraded.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| inSeconds | uint256 | The degradation period for the policy. |

### degradationFreshness

```solidity
function degradationFreshness(uint32 policyId) public view returns (uint256 inSeconds)
```

A service may implement a mitigation strategy to employ while the service is degraded.

_Service mitigations can use this parameter._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| inSeconds | uint256 | The freshness period for the policy. |

### mitigationCutoff

```solidity
function mitigationCutoff(uint32 policyId) public view returns (uint256 cutoffTime)
```

Service degradation mitigation measures depend on the oldest acceptable update.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to consult for a cutoff time. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| cutoffTime | uint256 | The oldest update that will be useable for mitigation measures. |

## ExemptionsManager

This contract manages the exemptions for the policy engine.
It allows an exemptions admin to manage global exemptions and policy admins
to manage policy-specific exemptions.

_Inherits from IExemptionsManager, KeyringAccessControl, and Initializable._

### ROLE_GLOBAL_EXEMPTIONS_ADMIN

```solidity
bytes32 ROLE_GLOBAL_EXEMPTIONS_ADMIN
```

### policyManager

```solidity
address policyManager
```

### exemptionDescriptions

```solidity
mapping(address => string) exemptionDescriptions
```

### onlyExemptionsAdmin

```solidity
modifier onlyExemptionsAdmin()
```

Keyring Governance has exclusive access to global exemptions.

_Reverts if the user doesn't have the global validation admin role._

### onlyPolicyAdmin

```solidity
modifier onlyPolicyAdmin(uint32 policyId)
```

Only the Policy Admin can manipulate policy-specific settings.

_Reverts if the sender is not an admin for the specified policy._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId to check. |

### constructor

```solidity
constructor(address trustedForwarder) public
```

### init

```solidity
function init(address policyManager_) external
```

Initializes the contract with the provided policyManager address.

_Can only be called once, as it is an initializer function._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyManager_ | address | The address of the PolicyManager contract. |

### admitGlobalExemption

```solidity
function admitGlobalExemption(address[] exemptAddresses, string description) external
```

Admits the specified addresses as global exemptions with a description.

_Can only be called by the exemptions admin. Admission is irrevocable._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| exemptAddresses | address[] | An array of addresses to be admitted as global exemptions. |
| description | string | A human-readable description of the exempt addresses. |

### updateGlobalExemption

```solidity
function updateGlobalExemption(address exemptAddress, string description) external
```

Updates the description of an existing global exemption address.

_Can only be called by the exemptions admin._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| exemptAddress | address | The exempt address whose description needs to be updated. |
| description | string | The new human-readable description for the exempt address. |

### _updateGlobalExemption

```solidity
function _updateGlobalExemption(address exemptAddress, string description) internal
```

### approvePolicyExemptions

```solidity
function approvePolicyExemptions(uint32 policyId, address[] exemptions) external
```

Approves the specified exemptions for a given policy.

_Can only be called by a policy admin for the specified policyId. Only policies
that are admitted globally are eligable for approval. Approval is irrevocable._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy for which exemptions are being approved. |
| exemptions | address[] | An array of addresses to be approved as exemptions for the policy. |

### globalExemptionsCount

```solidity
function globalExemptionsCount() external view returns (uint256 count)
```

Returns the count of global exemptions.

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The count of global exemptions. |

### globalExemptionAtIndex

```solidity
function globalExemptionAtIndex(uint256 index) external view returns (address exemption)
```

Returns the global exemption address at the specified index.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | The index of the exemption in the global exemptions list. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| exemption | address | The global exemption address at the specified index. |

### isGlobalExemption

```solidity
function isGlobalExemption(address exemption) public view returns (bool isIndeed)
```

Checks if a given address is a global exemption.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| exemption | address | The address to be checked as a global exemption. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the address is a global exemption, otherwise false. |

### policyExemptionsCount

```solidity
function policyExemptionsCount(uint32 policyId) external view returns (uint256 count)
```

Returns the count of policy-specific exemptions for a given policyId.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy for which exemptions count is required. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The count of exemptions for the given policyId. |

### policyExemptionAtIndex

```solidity
function policyExemptionAtIndex(uint32 policyId, uint256 index) external view returns (address exemption)
```

Returns the policy-specific exemption address at the specified index for a given policyId.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy for which the exemption is required. |
| index | uint256 | The index of the exemption in the policy exemptions list. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| exemption | address | The exemption address at the specified index. |

### isPolicyExemption

```solidity
function isPolicyExemption(uint32 policyId, address exemption) external view returns (bool isIndeed)
```

Checks if a given address is an exemption for a specified policyId.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy for which the exemption check is required. |
| exemption | address | The address to be checked as an exemption for the policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the address is an exemption for the policy, otherwise false. |

## IdentityTree

This contract holds the history of identity tree merkle roots announced by the aggregator. 
 Each root has an associated birthday that records when it was created. Zero-knowledge proofs rely
 on these roots. Claims supported by proofs are considered to be of the same age as the roots they
 rely on for validity.

### ROLE_AGGREGATOR

```solidity
bytes32 ROLE_AGGREGATOR
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
constructor(address trustedForwarder_, address policyManager_, uint256 maximumConsentPeriod_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder_ | address | Contract address that is allowed to relay message signers. |
| policyManager_ | address | The policy manager contract address. |
| maximumConsentPeriod_ | uint256 | The maximum allowable user consent period. |

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

### checkRoot

```solidity
function checkRoot(address observer, bytes32 merkleRoot, uint32 admissionPolicyId) external returns (bool passed)
```

Inspect the Identity Tree

_Use static calls to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The observer for degradation mitigation consent. |
| merkleRoot | bytes32 | The merkle root to inspect. |
| admissionPolicyId | uint32 | The admission policy for the credential to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| passed | bool | True if a valid merkle root exists or if mitigation measures are applicable. |

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

### latestRoot

```solidity
function latestRoot() external view returns (bytes32 root)
```

Return the lastest merkle root recorded. 
     @return root The latest merkle root recorded.

## KeyringGuard

KeyringGuard implementation that uses immutable configuration parameters and presents 
a simplified modifier for use in derived contracts.

### NULL_ADDRESS

```solidity
address NULL_ADDRESS
```

### keyringCredentials

```solidity
address keyringCredentials
```

### policyManager

```solidity
address policyManager
```

### userPolicies

```solidity
address userPolicies
```

### exemptionsManager

```solidity
address exemptionsManager
```

### admissionPolicyId

```solidity
uint32 admissionPolicyId
```

### universeRule

```solidity
bytes32 universeRule
```

### emptyRule

```solidity
bytes32 emptyRule
```

### checkKeyring

```solidity
modifier checkKeyring(address from, address to)
```

_Modifier checks ZK credentials and trader wallets for sender and receiver._

### constructor

```solidity
constructor(struct IKeyringGuard.KeyringConfig config, uint32 admissionPolicyId_, uint32 maximumConsentPeriod_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| config | struct IKeyringGuard.KeyringConfig | Keyring contract addresses. |
| admissionPolicyId_ | uint32 | The unique identifier of a Policy against which user accounts will be compared. |
| maximumConsentPeriod_ | uint32 | The upper limit for user consent deadlines. |

### checkZKPIICache

```solidity
function checkZKPIICache(address observer, address subject) public returns (bool passed)
```

Checks keyringCache for cached PII credential.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The user who must consent to reliance on degraded services. |
| subject | address | The subject to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| passed | bool | True if cached credential is new enough, or if degraded service mitigation is possible and the user has provided consent. |

### checkTraderWallet

```solidity
function checkTraderWallet(address observer, address subject) public returns (bool passed)
```

Check the trader wallet against all wallet checks in the policy configuration.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The user who must consent to reliance on degraded services. |
| subject | address | The subject to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| passed | bool | True if the wallet check is new enough, or if the degraded service mitigation is possible and the user has provided consent. |

### isAuthorized

```solidity
function isAuthorized(address from, address to) public returns (bool passed)
```

Check from and to addresses for compliance.

_Both parties are compliant, where compliant means:
 - they have a cached credential and if required, a wallet check 
 - they are an approved counterparty of the other party
 - they can rely on degraded service mitigation, and their counterparty consents
 - the policy exempts them from compliance checks, usually reserved for contracts_

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| from | address | First trader wallet to inspect. |
| to | address | Second trader wallet to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| passed | bool | True, if both parties are compliant. |

## IConsent

### GrantDegradedServiceConsent

```solidity
event GrantDegradedServiceConsent(address user, uint256 revocationDeadline)
```

### RevokeDegradedServiceConsent

```solidity
event RevokeDegradedServiceConsent(address user)
```

### maximumConsentPeriod

```solidity
function maximumConsentPeriod() external view returns (uint256)
```

### userConsentDeadlines

```solidity
function userConsentDeadlines(address user) external view returns (uint256)
```

### grantDegradedServiceConsent

```solidity
function grantDegradedServiceConsent(uint256 revocationDeadline) external
```

### revokeMitigationConsent

```solidity
function revokeMitigationConsent() external
```

### userConsentsToMitigation

```solidity
function userConsentsToMitigation(address user) external view returns (bool doesIndeed)
```

## IDegradable

### SetPolicyParameters

```solidity
event SetPolicyParameters(address admin, uint32 policyId, uint256 degradationPeriod, uint256 degradationFreshness)
```

### MitigationParameters

```solidity
struct MitigationParameters {
  uint256 degradationPeriod;
  uint256 degradationFreshness;
}
```

### ROLE_SERVICE_SUPERVISOR

```solidity
function ROLE_SERVICE_SUPERVISOR() external view returns (bytes32)
```

### defaultDegradationPeriod

```solidity
function defaultDegradationPeriod() external view returns (uint256)
```

### defaultFreshnessPeriod

```solidity
function defaultFreshnessPeriod() external view returns (uint256)
```

### policyManager

```solidity
function policyManager() external view returns (address)
```

### lastUpdate

```solidity
function lastUpdate() external view returns (uint256)
```

### subjectUpdates

```solidity
function subjectUpdates(bytes32 subject) external view returns (uint256 timestamp)
```

### setPolicyParameters

```solidity
function setPolicyParameters(uint32 policyId, uint256 degradationPeriod, uint256 degradationFreshness) external
```

### canMitigate

```solidity
function canMitigate(address observer, bytes32 subject, uint32 policyId) external view returns (bool canIndeed)
```

### isDegraded

```solidity
function isDegraded(uint32 policyId) external view returns (bool isIndeed)
```

### isMitigationQualified

```solidity
function isMitigationQualified(bytes32 subject, uint32 policyId) external view returns (bool qualifies)
```

### degradationPeriod

```solidity
function degradationPeriod(uint32 policyId) external view returns (uint256 inSeconds)
```

### degradationFreshness

```solidity
function degradationFreshness(uint32 policyId) external view returns (uint256 inSeconds)
```

### mitigationCutoff

```solidity
function mitigationCutoff(uint32 policyId) external view returns (uint256 cutoffTime)
```

## IExemptionsManager

### ExemptionsManagerInitialized

```solidity
event ExemptionsManagerInitialized(address admin, address policyManager)
```

### AdmitGlobalExemption

```solidity
event AdmitGlobalExemption(address admin, address exemption, string description)
```

### UpdateGlobalExemption

```solidity
event UpdateGlobalExemption(address admin, address exemption, string description)
```

### ApprovePolicyExemptions

```solidity
event ApprovePolicyExemptions(address admin, uint32 policyId, address exemption)
```

### ROLE_GLOBAL_EXEMPTIONS_ADMIN

```solidity
function ROLE_GLOBAL_EXEMPTIONS_ADMIN() external view returns (bytes32)
```

### policyManager

```solidity
function policyManager() external view returns (address)
```

### exemptionDescriptions

```solidity
function exemptionDescriptions(address) external view returns (string)
```

### init

```solidity
function init(address policyManager_) external
```

### admitGlobalExemption

```solidity
function admitGlobalExemption(address[] exemptAddresses, string description) external
```

### updateGlobalExemption

```solidity
function updateGlobalExemption(address exemptAddress, string description) external
```

### approvePolicyExemptions

```solidity
function approvePolicyExemptions(uint32 policyId, address[] exemptions) external
```

### globalExemptionsCount

```solidity
function globalExemptionsCount() external view returns (uint256 count)
```

### globalExemptionAtIndex

```solidity
function globalExemptionAtIndex(uint256 index) external view returns (address exemption)
```

### isGlobalExemption

```solidity
function isGlobalExemption(address exemption) external view returns (bool isIndeed)
```

### policyExemptionsCount

```solidity
function policyExemptionsCount(uint32 policyId) external view returns (uint256 count)
```

### policyExemptionAtIndex

```solidity
function policyExemptionAtIndex(uint32 policyId, uint256 index) external view returns (address exemption)
```

### isPolicyExemption

```solidity
function isPolicyExemption(uint32 policyId, address exemption) external view returns (bool isIndeed)
```

## IIdentityTree

### Deployed

```solidity
event Deployed(address admin, address trustedForwarder_, address policyManager_, uint256 maximumConsentPeriod)
```

### SetMerkleRootBirthday

```solidity
event SetMerkleRootBirthday(bytes32 merkleRoot, uint256 birthday)
```

### PolicyMitigation

```solidity
struct PolicyMitigation {
  uint256 mitigationFreshness;
  uint256 degradationPeriod;
}
```

### ROLE_AGGREGATOR

```solidity
function ROLE_AGGREGATOR() external view returns (bytes32)
```

### setMerkleRootBirthday

```solidity
function setMerkleRootBirthday(bytes32 root, uint256 birthday) external
```

### checkRoot

```solidity
function checkRoot(address observer, bytes32 merkleRoot, uint32 admissionPolicyId) external returns (bool passed)
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

### latestRoot

```solidity
function latestRoot() external view returns (bytes32 root)
```

## IKeyringCredentials

### CredentialsDeployed

```solidity
event CredentialsDeployed(address deployer, address trustedForwarder, address policyManager, uint256 maximumConsentPeriod)
```

### CredentialsInitialized

```solidity
event CredentialsInitialized(address admin)
```

### UpdateCredential

```solidity
event UpdateCredential(uint8 version, address updater, address trader, uint32 admissionPolicyId)
```

### ROLE_CREDENTIAL_UPDATER

```solidity
function ROLE_CREDENTIAL_UPDATER() external view returns (bytes32)
```

### init

```solidity
function init() external
```

### setCredential

```solidity
function setCredential(address trader, uint32 admissionPolicyId, uint256 timestamp) external
```

### checkCredential

```solidity
function checkCredential(address observer, address subject, uint32 admissionPolicyId) external returns (bool passed)
```

### keyGen

```solidity
function keyGen(address trader, uint32 admissionPolicyId) external pure returns (bytes32 key)
```

## IKeyringGuard

KeyringGuard implementation that uses immutables and presents a simplified modifier.

### KeyringConfig

```solidity
struct KeyringConfig {
  address trustedForwarder;
  address collateralToken;
  address keyringCredentials;
  address policyManager;
  address userPolicies;
  address exemptionsManager;
}
```

### KeyringGuardConfigured

```solidity
event KeyringGuardConfigured(address keyringCredentials, address policyManager, address userPolicies, uint32 admissionPolicyId, bytes32 universeRule, bytes32 emptyRule)
```

### checkZKPIICache

```solidity
function checkZKPIICache(address observer, address subject) external returns (bool passed)
```

### checkTraderWallet

```solidity
function checkTraderWallet(address observer, address subject) external returns (bool passed)
```

### isAuthorized

```solidity
function isAuthorized(address from, address to) external returns (bool passed)
```

## IKeyringProofVerifier

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[] input) external view returns (bool isValid)
```

## IKeyringZkCredentialUpdater

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
function updateCredentials(address attestor, struct IKeyringZkVerifier.IdentityMembershipProof membershipProof, struct IKeyringZkVerifier.IdentityAuthorisationProof authorizationProof) external
```

### checkPolicy

```solidity
function checkPolicy(uint32 policyId, address attestor) external returns (bool acceptable)
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

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### Deployed

```solidity
event Deployed(address deployer, address identityConstructionProofVerifier, address membershipProofVerifier, address authorisationProofVerifier)
```

### Backdoor

```solidity
struct Backdoor {
  uint256[2] c1;
  uint256[2] c2;
}
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
  uint256[71] inputs;
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
  struct IKeyringZkVerifier.Backdoor backdoor;
  uint256 externalNullifier;
  uint256 nullifierHash;
  uint256[2] policyDisclosures;
  uint256 tradingAddress;
  uint256[2] regimeKey;
}
```

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

### DisablePolicy

```solidity
event DisablePolicy(address user, uint32 policyId)
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

### UpdatePolicyTtl

```solidity
event UpdatePolicyTtl(address owner, uint32 policyId, uint128 ttl, uint256 deadline)
```

### UpdatePolicyGracePeriod

```solidity
event UpdatePolicyGracePeriod(address owner, uint32 policyId, uint128 gracePeriod, uint256 deadline)
```

### UpdatePolicyLock

```solidity
event UpdatePolicyLock(address owner, uint32 policyId, bool locked, uint256 deadline)
```

### UpdatePolicyAllowApprovedCounterparties

```solidity
event UpdatePolicyAllowApprovedCounterparties(address owner, uint32 policyId, bool allowApprovedCounterparties, uint256 deadline)
```

### UpdatePolicyDisablementPeriod

```solidity
event UpdatePolicyDisablementPeriod(address admin, uint32 policyId, uint256 disablementPeriod, uint256 deadline)
```

### PolicyDisabled

```solidity
event PolicyDisabled(address sender, uint32 policyId)
```

### UpdatePolicyDeadline

```solidity
event UpdatePolicyDeadline(address owner, uint32 policyId, uint256 deadline)
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

### AddPolicyBackdoor

```solidity
event AddPolicyBackdoor(address owner, uint32 policyId, bytes32 backdoorId, uint256 deadline)
```

### RemovePolicyBackdoor

```solidity
event RemovePolicyBackdoor(address owner, uint32 policyId, bytes32 backdoorId, uint256 deadline)
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

### AdmitBackdoor

```solidity
event AdmitBackdoor(address admin, bytes32 id, uint256[2] pubKey)
```

### MinimumPolicyDisablementPeriodUpdated

```solidity
event MinimumPolicyDisablementPeriodUpdated(uint256 newPeriod)
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

### ROLE_GLOBAL_VALIDATION_ADMIN

```solidity
function ROLE_GLOBAL_VALIDATION_ADMIN() external view returns (bytes32)
```

### ROLE_GLOBAL_BACKDOOR_ADMIN

```solidity
function ROLE_GLOBAL_BACKDOOR_ADMIN() external view returns (bytes32)
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

### disablePolicy

```solidity
function disablePolicy(uint32 policyId) external
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

### updatePolicyAllowApprovedCounterparties

```solidity
function updatePolicyAllowApprovedCounterparties(uint32 policyId, bool allowApprovedCounterparties, uint256 deadline) external
```

### updatePolicyLock

```solidity
function updatePolicyLock(uint32 policyId, bool locked, uint256 deadline) external
```

### updatePolicyDisablementPeriod

```solidity
function updatePolicyDisablementPeriod(uint32 policyId, uint256 disablementPeriod, uint256 deadline) external
```

### setDeadline

```solidity
function setDeadline(uint32 policyId, uint256 deadline) external
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

### addPolicyBackdoor

```solidity
function addPolicyBackdoor(uint32 policyId, bytes32 backdoorId, uint256 deadline) external
```

### removePolicyBackdoor

```solidity
function removePolicyBackdoor(uint32 policyId, bytes32 backdoorId, uint256 deadline) external
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

### admitBackdoor

```solidity
function admitBackdoor(uint256[2] pubKey) external
```

### updateMinimumPolicyDisablementPeriod

```solidity
function updateMinimumPolicyDisablementPeriod(uint256 minimumDisablementPeriod) external
```

### policyOwnerRole

```solidity
function policyOwnerRole(uint32 policyId) external pure returns (bytes32 ownerRole)
```

### policy

```solidity
function policy(uint32 policyId) external returns (struct PolicyStorage.PolicyScalar scalar, address[] attestors, address[] walletChecks, bytes32[] backdoorRegimes, uint256 deadline)
```

### policyRawData

```solidity
function policyRawData(uint32 policyId) external view returns (uint256 deadline, struct PolicyStorage.PolicyScalar scalarActive, struct PolicyStorage.PolicyScalar scalarPending, address[] attestorsActive, address[] attestorsPendingAdditions, address[] attestorsPendingRemovals, address[] walletChecksActive, address[] walletChecksPendingAdditions, address[] walletChecksPendingRemovals, bytes32[] backdoorsActive, bytes32[] backdoorsPendingAdditions, bytes32[] backdoorsPendingRemovals)
```

### policyScalarActive

```solidity
function policyScalarActive(uint32 policyId) external returns (struct PolicyStorage.PolicyScalar scalarActive)
```

### policyRuleId

```solidity
function policyRuleId(uint32 policyId) external returns (bytes32 ruleId)
```

### policyTtl

```solidity
function policyTtl(uint32 policyId) external returns (uint32 ttl)
```

### policyAllowApprovedCounterparties

```solidity
function policyAllowApprovedCounterparties(uint32 policyId) external returns (bool isAllowed)
```

### policyDisabled

```solidity
function policyDisabled(uint32 policyId) external view returns (bool isDisabled)
```

### policyCanBeDisabled

```solidity
function policyCanBeDisabled(uint32 policyId) external returns (bool canIndeed)
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

### policyBackdoorCount

```solidity
function policyBackdoorCount(uint32 policyId) external returns (uint256 count)
```

### policyBackdoorAtIndex

```solidity
function policyBackdoorAtIndex(uint32 policyId, uint256 index) external returns (bytes32 backdoorId)
```

### policyBackdoors

```solidity
function policyBackdoors(uint32 policyId) external returns (bytes32[] backdoors)
```

### isPolicyBackdoor

```solidity
function isPolicyBackdoor(uint32 policyId, bytes32 backdoorId) external returns (bool isIndeed)
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

### globalBackdoorCount

```solidity
function globalBackdoorCount() external view returns (uint256 count)
```

### globalBackdoorAtIndex

```solidity
function globalBackdoorAtIndex(uint256 index) external view returns (bytes32 backdoorId)
```

### isGlobalBackdoor

```solidity
function isGlobalBackdoor(bytes32 backdoorId) external view returns (bool isIndeed)
```

### backdoorPubKey

```solidity
function backdoorPubKey(bytes32 backdoorId) external view returns (uint256[2] pubKey)
```

### attestorUri

```solidity
function attestorUri(address attestor) external view returns (string)
```

### hasRole

```solidity
function hasRole(bytes32 role, address user) external view returns (bool)
```

### minimumPolicyDisablementPeriod

```solidity
function minimumPolicyDisablementPeriod() external view returns (uint256 period)
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
  struct Bytes32Set.Set operandSet;
  enum IRuleRegistry.Operator operator;
  bool toxic;
}
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

## IUserPolicies

### Deployed

```solidity
event Deployed(address trustedForwarder, address policyManager)
```

### SetUserPolicy

```solidity
event SetUserPolicy(address trader, uint32 policyId)
```

### AddApprovedCounterparty

```solidity
event AddApprovedCounterparty(address, address approved)
```

### RemoveApprovedCounterparty

```solidity
event RemoveApprovedCounterparty(address, address approved)
```

### userPolicies

```solidity
function userPolicies(address trader) external view returns (uint32)
```

### setUserPolicy

```solidity
function setUserPolicy(uint32 policyId) external
```

### addApprovedCounterparty

```solidity
function addApprovedCounterparty(address approved) external
```

### addApprovedCounterparties

```solidity
function addApprovedCounterparties(address[] approved) external
```

### removeApprovedCounterparty

```solidity
function removeApprovedCounterparty(address approved) external
```

### removeApprovedCounterparties

```solidity
function removeApprovedCounterparties(address[] approved) external
```

### approvedCounterpartyCount

```solidity
function approvedCounterpartyCount(address trader) external view returns (uint256 count)
```

### approvedCounterpartyAtIndex

```solidity
function approvedCounterpartyAtIndex(address trader, uint256 index) external view returns (address approved)
```

### isApproved

```solidity
function isApproved(address trader, address counterparty) external view returns (bool isIndeed)
```

## IWalletCheck

### Deployed

```solidity
event Deployed(address admin, address trustedForwarder, address policyManager, uint256 maximumConsentPeriod, string uri)
```

### UpdateUri

```solidity
event UpdateUri(address admin, string uri)
```

### SetWalletCheck

```solidity
event SetWalletCheck(address admin, address wallet, bool isWhitelisted)
```

### ROLE_WALLETCHECK_LIST_ADMIN

```solidity
function ROLE_WALLETCHECK_LIST_ADMIN() external view returns (bytes32)
```

### ROLE_WALLETCHECK_META_ADMIN

```solidity
function ROLE_WALLETCHECK_META_ADMIN() external view returns (bytes32)
```

### updateUri

```solidity
function updateUri(string uri_) external
```

### setWalletCheck

```solidity
function setWalletCheck(address wallet, bool whitelisted, uint256 timestamp) external
```

### checkWallet

```solidity
function checkWallet(address observer, address wallet, uint32 admissionPolicyId) external returns (bool passed)
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

### onlyUpdater

```solidity
modifier onlyUpdater()
```

Revert if the message sender doesn't have the Credentials updater role.

### constructor

```solidity
constructor(address trustedForwarder, address policyManager_, uint256 maximumConsentPeriod_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| policyManager_ | address | The deployed policyManager contract address. |
| maximumConsentPeriod_ | uint256 | The time limit for user consent to mitigation procedures. |

### init

```solidity
function init() external
```

This upgradeable contract must be initialized.
 @dev The initializer function MUST be called directly after deployment 
because anyone can call it but overall only once.

### setCredential

```solidity
function setCredential(address trader, uint32 admissionPolicyId, uint256 timestamp) external
```

This function is called by a trusted and permitted contract such as the 
KeyringZkCredentialUpdater. There is no prohibition on multiple proving schemes 
at the cache level since this contract requires only that the caller has permission.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The user address for the Credential update. |
| admissionPolicyId | uint32 | The unique identifier of a Policy. |
| timestamp | uint256 | The timestamp established by the credential updater. |

### checkCredential

```solidity
function checkCredential(address observer, address trader, uint32 admissionPolicyId) external returns (bool passed)
```

Inspect the credential cache.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The observer for degradation mitigation consent. |
| trader | address | The user address for the Credential update. |
| admissionPolicyId | uint32 | The admission policy for the credential to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| passed | bool | True if a valid cached credential exists or if mitigation measures are applicable. |

### keyGen

```solidity
function keyGen(address trader, uint32 admissionPolicyId) public pure returns (bytes32 key)
```

Generate a cache key for a trader and policyId.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The trader for the credential cache. |
| admissionPolicyId | uint32 | The policyId. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| key | bytes32 | The credential cache key. |

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
     @dev input order:
            NOTE - input order
            [
                constructionProof.policyCommitment,
                constructionProof.maxAddresses,
                constructionProof.regimeKey,
                constructionProof.identityPK,
                constructionProof.identityCommitment,
                constructionProof.cs
            ]
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
| self | struct AddressSet.Set | A Set struct |
| key | address | A key to insert cast as an address. |
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
| self | struct AddressSet.Set | A Set struct |
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
| self | struct AddressSet.Set | A Set struct |

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
| self | struct AddressSet.Set | A Set struct |
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
| self | struct AddressSet.Set | A Set struct |
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

### Bytes32SetConsistency

```solidity
error Bytes32SetConsistency(string module, string method, string reason, string context)
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
| self | struct Bytes32Set.Set | A Set struct |
| key | bytes32 | A value in the Set. |
| context | string | A message string about interpretation of the issue. Normally the calling function. |

### remove

```solidity
function remove(struct Bytes32Set.Set self, bytes32 key, string context) internal
```

Remove a key from the store.

_The key to remove must exist._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Set struct |
| key | bytes32 | An address to remove from the Set. |
| context | string | A message string about interpretation of the issue. Normally the calling function. |

### count

```solidity
function count(struct Bytes32Set.Set self) internal view returns (uint256)
```

Count the keys.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct Bytes32Set.Set | A Set struct |

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
| self | struct Bytes32Set.Set | A Set struct |
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
| self | struct Bytes32Set.Set | A Set struct |
| index | uint256 | The position in the Set to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bytes32 | bytes32 The key stored in the Set at the index position. |

## Pack12x20

### OutOfRange

```solidity
error OutOfRange(uint32 input)
```

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
     @dev uint32 Inputs are limited to 20 bits of magnitude.
     @param input Array of 20-bit integers to pack cast as an array of uint32.

### unpack

```solidity
function unpack(uint256 packed) internal pure returns (uint32[12] output)
```

Unpack 12 20-bit integers from 240-bit input
     @dev Data beyond the first 240 bits is ignored.
     @param packed 12 20-bit integers packed into 240 bits.
     @return output 12 20-bit integers cast as an array of 32-bit integers.

## PolicyStorage

PolicyStorage attends to state management concerns for the PolicyManager. It establishes the
 storage layout and is responsible for internal state integrity and managing state transitions. The 
 PolicyManager is responsible for orchestration of the functions implemented here as well as access
 control.

### MAX_DISABLEMENT_PERIOD

```solidity
uint256 MAX_DISABLEMENT_PERIOD
```

### Unacceptable

```solidity
error Unacceptable(string reason)
```

### App

```solidity
struct App {
  uint256 minimumPolicyDisablementPeriod;
  struct PolicyStorage.Policy[] policies;
  struct AddressSet.Set globalWalletCheckSet;
  struct AddressSet.Set globalAttestorSet;
  mapping(address => string) attestorUris;
  struct Bytes32Set.Set backdoorSet;
  mapping(bytes32 => uint256[2]) backdoorPubKey;
}
```

### PolicyScalar

```solidity
struct PolicyScalar {
  bytes32 ruleId;
  string descriptionUtf8;
  uint32 ttl;
  uint32 gracePeriod;
  bool allowApprovedCounterparties;
  uint256 disablementPeriod;
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

### PolicyBackdoors

```solidity
struct PolicyBackdoors {
  struct Bytes32Set.Set activeSet;
  struct Bytes32Set.Set pendingAdditionSet;
  struct Bytes32Set.Set pendingRemovalSet;
}
```

### Policy

```solidity
struct Policy {
  bool disabled;
  uint256 deadline;
  struct PolicyStorage.PolicyScalar scalarActive;
  struct PolicyStorage.PolicyScalar scalarPending;
  struct PolicyStorage.PolicyAttestors attestors;
  struct PolicyStorage.PolicyWalletChecks walletChecks;
  struct PolicyStorage.PolicyBackdoors backdoors;
}
```

### disablePolicy

```solidity
function disablePolicy(struct PolicyStorage.Policy policyObj) public
```

A policy can be disabled if the policy is deemed failed.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | The policy to disable. |

### policyHasFailed

```solidity
function policyHasFailed(struct PolicyStorage.Policy policyObj) public view returns (bool hasIndeed)
```

A policy is deemed failed if all attestors or any wallet check is inactive
over the policyDisablement period.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| hasIndeed | bool | True if all attestors have failed or any wallet check has failed,       where "failure" is no updates over the policyDisablement period. |

### updateMinimumPolicyDisablementPeriod

```solidity
function updateMinimumPolicyDisablementPeriod(struct PolicyStorage.App self, uint256 minimumDisablementPeriod) public
```

Updates the minimumPolicyDisablementPeriod property of the Policy struct.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | A storage reference to the App storage |
| minimumDisablementPeriod | uint256 | The new value for the minimumPolicyDisablementPeriod property. |

### insertGlobalAttestor

```solidity
function insertGlobalAttestor(struct PolicyStorage.App self, address attestor, string uri) public
```

The attestor admin can admit attestors into the global attestor whitelist.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| attestor | address | Address of the attestor's identity tree contract. |
| uri | string | The URI refers to detailed information about the attestor. |

### updateGlobalAttestorUri

```solidity
function updateGlobalAttestorUri(struct PolicyStorage.App self, address attestor, string uri) public
```

The attestor admin can update the informational URIs for attestors on the whitelist.

_No onchain logic relies on the URI._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| attestor | address | Address of an attestor's identity tree contract on the whitelist. |
| uri | string | The URI refers to detailed information about the attestor. |

### removeGlobalAttestor

```solidity
function removeGlobalAttestor(struct PolicyStorage.App self, address attestor) public
```

The attestor admin can remove attestors from the whitelist.

_Does not remove attestors from policies that recognise the attestor to remove._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| attestor | address | Address of an attestor identity tree to remove from the whitelist. |

### insertGlobalWalletCheck

```solidity
function insertGlobalWalletCheck(struct PolicyStorage.App self, address walletCheck) public
```

The wallet check admin can admit wallet check contracts into the system.

_Wallet checks implement the IWalletCheck interface._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| walletCheck | address | The address of a Wallet Check to admit into the global whitelist. |

### removeGlobalWalletCheck

```solidity
function removeGlobalWalletCheck(struct PolicyStorage.App self, address walletCheck) public
```

The wallet check admin can remove a wallet check from the system.

_Does not affect policies that utilize the wallet check._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| walletCheck | address | The address of a Wallet Check to admit into the global whitelist. |

### insertGlobalBackdoor

```solidity
function insertGlobalBackdoor(struct PolicyStorage.App self, uint256[2] pubKey) public returns (bytes32 id)
```

The backdoor admin can add a backdoor.

_pubKey must be unique._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| pubKey | uint256[2] | The public key for backdoor encryption. |

### newPolicy

```solidity
function newPolicy(struct PolicyStorage.App self, struct PolicyStorage.PolicyScalar policyScalar, address[] attestors, address[] walletChecks, address ruleRegistry) public returns (uint32 policyId)
```

Creates a new policy that is owned by the creator.

_Maximum unique policies is 2 ^ 20. Must be at least 1 attestor._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| policyScalar | struct PolicyStorage.PolicyScalar | The new policy's non-indexed values. |
| attestors | address[] | A list of attestor identity tree contracts. |
| walletChecks | address[] | The address of one or more Wallet Checks to add to the Policy. |
| ruleRegistry | address | The address of the deployed RuleRegistry contract. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | A PolicyStorage struct.Id The unique identifier of a Policy. |

### policyRawData

```solidity
function policyRawData(struct PolicyStorage.App self, uint32 policyId) public view returns (struct PolicyStorage.Policy policyInfo)
```

Returns the internal policy state without processing staged changes.

_Staged changes with deadlines in the past are presented as pending._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| policyId | uint32 | A PolicyStorage struct.Id The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyInfo | struct PolicyStorage.Policy | Policy info in the internal storage format without processing. |

### processStaged

```solidity
function processStaged(struct PolicyStorage.Policy policyObj) public
```

Processes staged changes to the policy state if the deadline is in the past.

_Always call this before inspecting the the active policy state. ._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | A Policy object. |

### checkLock

```solidity
function checkLock(struct PolicyStorage.Policy policyObj) public view
```

Prevents changes to locked and disabled Policies.

_Reverts if the active policy lock is set to true or the Policy is disabled._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | A Policy object. |

### isLocked

```solidity
function isLocked(struct PolicyStorage.Policy policyObj) public view returns (bool isIndeed)
```

Inspect the active policy lock.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | A Policy object. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the active policy locked parameter is set to true. True value if PolicyStorage      is locked, otherwise False. |

### setDeadline

```solidity
function setDeadline(struct PolicyStorage.Policy policyObj, uint256 deadline) public
```

Processes staged changes if the current deadline has passed and updates the deadline.

_The deadline must be at least as far in the future as the active policy gracePeriod._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | A Policy object. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### writePolicyScalar

```solidity
function writePolicyScalar(struct PolicyStorage.App self, uint32 policyId, struct PolicyStorage.PolicyScalar policyScalar, address ruleRegistry, uint256 deadline) public
```

Non-indexed Policy values can be updated in one step.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| policyId | uint32 | A PolicyStorage struct.Id The unique identifier of a Policy. |
| policyScalar | struct PolicyStorage.PolicyScalar | The new non-indexed properties. |
| ruleRegistry | address | The address of the deployed RuleRegistry contract. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### writeRuleId

```solidity
function writeRuleId(struct PolicyStorage.Policy self, bytes32 ruleId, address ruleRegistry) public
```

Writes a new RuleId to the pending Policy changes in a Policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| ruleId | bytes32 | The unique identifier of a Rule. |
| ruleRegistry | address | The address of the deployed RuleRegistry contract. |

### writeDescription

```solidity
function writeDescription(struct PolicyStorage.Policy self, string descriptionUtf8) public
```

Writes a new descriptionUtf8 to the pending Policy changes in a Policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| descriptionUtf8 | string | Policy description in UTF-8 format. |

### writeTtl

```solidity
function writeTtl(struct PolicyStorage.Policy self, uint32 ttl) public
```

Writes a new ttl to the pending Policy changes in a Policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| ttl | uint32 | The maximum acceptable credential age in seconds. |

### writeGracePeriod

```solidity
function writeGracePeriod(struct PolicyStorage.Policy self, uint32 gracePeriod) public
```

Writes a new gracePeriod to the pending Policy changes in a Policy.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| gracePeriod | uint32 | The minimum acceptable deadline. |

### writeAllowApprovedCounterparties

```solidity
function writeAllowApprovedCounterparties(struct PolicyStorage.Policy self, bool allowApprovedCounterparties) public
```

Writes a new allowApprovedCounterparties state in the pending Policy changes in a Policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| allowApprovedCounterparties | bool | True if whitelists are allowed, otherwise false. |

### writePolicyLock

```solidity
function writePolicyLock(struct PolicyStorage.Policy self, bool setPolicyLocked) public
```

Writes a new locked state in the pending Policy changes in a Policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| setPolicyLocked | bool | True if the policy is to be locked, otherwise false. |

### writeDisablementPeriod

```solidity
function writeDisablementPeriod(struct PolicyStorage.App self, uint32 policyId, uint256 disablementPeriod) public
```

Writes a new disablement deadline to the pending Policy changes of a Policy.

_If the provided disablement deadline is in the past, this function will revert._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | A PolicyStorage object. |
| policyId | uint32 |  |
| disablementPeriod | uint256 | The new disablement deadline to set, in seconds since the Unix epoch.   If set to 0, the policy can be disabled at any time.   If set to a non-zero value, the policy can only be disabled after that time. |

### writeAttestorAdditions

```solidity
function writeAttestorAdditions(struct PolicyStorage.App self, struct PolicyStorage.Policy policyObj, address[] attestors) public
```

Writes attestors to pending Policy attestor additions.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| policyObj | struct PolicyStorage.Policy | A Policy object. |
| attestors | address[] | The address of one or more Attestors to add to the Policy. |

### writeAttestorRemovals

```solidity
function writeAttestorRemovals(struct PolicyStorage.Policy self, address[] attestors) public
```

Writes attestors to pending Policy attestor removals.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| attestors | address[] | The address of one or more Attestors to remove from the Policy. |

### writeWalletCheckAdditions

```solidity
function writeWalletCheckAdditions(struct PolicyStorage.App self, struct PolicyStorage.Policy policyObj, address[] walletChecks) public
```

Writes wallet checks to a Policy's pending wallet check additions.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | PolicyManager App state. |
| policyObj | struct PolicyStorage.Policy | A PolicyStorage object. |
| walletChecks | address[] | The address of one or more Wallet Checks to add to the Policy. |

### writeWalletCheckRemovals

```solidity
function writeWalletCheckRemovals(struct PolicyStorage.Policy self, address[] walletChecks) public
```

Writes wallet checks to a Policy's pending wallet check removals.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| walletChecks | address[] | The address of one or more Wallet Checks to add to the Policy. |

### writeBackdoorAddition

```solidity
function writeBackdoorAddition(struct PolicyStorage.App self, struct PolicyStorage.Policy policyObj, bytes32 backdoorId) public
```

Add a backdoor to a policy.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | The application state. |
| policyObj | struct PolicyStorage.Policy | A Policy object. |
| backdoorId | bytes32 | The ID of a backdoor. |

### writeBackdoorRemoval

```solidity
function writeBackdoorRemoval(struct PolicyStorage.Policy self, bytes32 backdoorId) public
```

Writes a wallet check to a Policy's pending wallet check removals.

_Unschedules addition if the wallet check is present in the Policy's pending wallet check additions._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A Policy object. |
| backdoorId | bytes32 | The address of a Wallet Check to remove from the Policy. |

### _checkBackdoorConfiguration

```solidity
function _checkBackdoorConfiguration(struct PolicyStorage.Policy self) internal view
```

Checks the net count of backdoors.

_Current zkVerifier supports only one backdoor per policy._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.Policy | A policy object. |

### policy

```solidity
function policy(struct PolicyStorage.App self, uint32 policyId) public returns (struct PolicyStorage.Policy policyObj)
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| self | struct PolicyStorage.App | Application state. |
| policyId | uint32 | The unique identifier of a Policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyObj | struct PolicyStorage.Policy | Policy object with staged updates processed. |

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
function isRule(bytes32) public pure returns (bool isIndeed)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | Usually true value if Rule exists, otherwise False. Always true in this case. |

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

### ROLE_GLOBAL_BACKDOOR_ADMIN

```solidity
bytes32 ROLE_GLOBAL_BACKDOOR_ADMIN
```

### ROLE_GLOBAL_VALIDATION_ADMIN

```solidity
bytes32 ROLE_GLOBAL_VALIDATION_ADMIN
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

### onlyBackdoorAdmin

```solidity
modifier onlyBackdoorAdmin()
```

Keyring governance has exclusive access to the global whitelist of backdoor.

_Reverts if the user doesn't have the global backdoor admin role._

### onlyValidationAdmin

```solidity
modifier onlyValidationAdmin()
```

Keyring Governance has exclusive access to input validation parameters.

_Reverts if the user doesn't have the global validation admin role._

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
| policyScalar | struct PolicyStorage.PolicyScalar | The non-indexed values in a policy configuration as defined in PolicyStorage. |
| attestors | address[] | Acceptable attestors correspond to identity trees that will be used in      zero-knowledge proofs. Proofs cannot be generated, and therefore credentials cannot be      generated using roots that do not originate in an identity tree that is not explicitly      acceptable. |
| walletChecks | address[] | Trader wallets are optionally checked againt on-chain wallet checks on      a just-in-time basis. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of a new Policy. |
| policyOwnerRoleId | bytes32 |  |
| policyUserAdminRoleId | bytes32 |  |

### disablePolicy

```solidity
function disablePolicy(uint32 policyId) external
```

Any user can disable a policy if the policy is deemed failed.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to disable. |

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
| policyScalar | struct PolicyStorage.PolicyScalar | The non-indexed values in a policy configuration as defined in PolicyStorage. |
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

### updatePolicyAllowApprovedCounterparties

```solidity
function updatePolicyAllowApprovedCounterparties(uint32 policyId, bool allowApprovedCounterparties, uint256 deadline) external
```

Policy owners can allow users to set whitelists of counterparties to exempt from
     compliance checks.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| allowApprovedCounterparties | bool | True if whitelists are allowed, otherwise false. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyLock

```solidity
function updatePolicyLock(uint32 policyId, bool locked, uint256 deadline) external
```

Schedules policy locking if the policy is not already scheduled to be locked.

_Deadlines must always be >= the active policy grace period._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to lock. |
| locked | bool | True if the policy is to be locked. False if the scheduled lock is to be cancelled. |
| deadline | uint256 | The timestamp when the staged changes will take effect. Overrides previous deadline. |

### updatePolicyDisablementPeriod

```solidity
function updatePolicyDisablementPeriod(uint32 policyId, uint256 disablementPeriod, uint256 deadline) external
```

Update the disablement period of a policy. See disable Policy.

_This function updates the disablement period of the policy specified by `policyId` to `disablementPeriod`.
Only the policy admin can call this function._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The ID of the policy to update. |
| disablementPeriod | uint256 | The new disablement period for the policy. |
| deadline | uint256 |  |

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

### addPolicyBackdoor

```solidity
function addPolicyBackdoor(uint32 policyId, bytes32 backdoorId, uint256 deadline) external
```

The policy admin can add a backdoor.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| backdoorId | bytes32 | The UID of the backdoor to add. |
| deadline | uint256 |  |

### removePolicyBackdoor

```solidity
function removePolicyBackdoor(uint32 policyId, bytes32 backdoorId, uint256 deadline) external
```

The policy admin can remove a backdoor.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to update. |
| backdoorId | bytes32 | The UID of the backdoor to remove. |
| deadline | uint256 |  |

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

### admitBackdoor

```solidity
function admitBackdoor(uint256[2] pubKey) external
```

The backdoor admin can admit a backdoor.

_Key must be unique. Removing these keys is unsupported._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| pubKey | uint256[2] | The public key to admit. |

### updateMinimumPolicyDisablementPeriod

```solidity
function updateMinimumPolicyDisablementPeriod(uint256 minimumDisablementPeriod) external
```

_Updates the minimumPolicyDisablementPeriod_

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| minimumDisablementPeriod | uint256 | The new value for the minimumPolicyDisablementPeriod property. |

### policyOwnerRole

```solidity
function policyOwnerRole(uint32 policyId) public pure returns (bytes32 ownerRole)
```

Generate the corresponding admin/owner role for a policyId.

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ownerRole | bytes32 | The bytes32 owner role that corresponds to the policyId |

### policy

```solidity
function policy(uint32 policyId) public returns (struct PolicyStorage.PolicyScalar config, address[] attestors, address[] walletChecks, bytes32[] backdoors, uint256 deadline)
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
| backdoors | bytes32[] | The backdoor regimes applicable to the policy. |
| deadline | uint256 | The timestamp when staged changes will take effect. |

### policyRawData

```solidity
function policyRawData(uint32 policyId) external view returns (uint256 deadline, struct PolicyStorage.PolicyScalar scalarActive, struct PolicyStorage.PolicyScalar scalarPending, address[] attestorsActive, address[] attestorsPendingAdditions, address[] attestorsPendingRemovals, address[] walletChecksActive, address[] walletChecksPendingAdditions, address[] walletChecksPendingRemovals, bytes32[] backdoorsActive, bytes32[] backdoorsPendingAdditions, bytes32[] backdoorsPendingRemovals)
```

Reveals the internal state of the policy object without processing staged changes.

_A non-zero deadline in the past indicates that staged updates are already in effect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

### policyScalarActive

```solidity
function policyScalarActive(uint32 policyId) external returns (struct PolicyStorage.PolicyScalar scalarActive)
```

Inspect the active policy scalar values.

_Use static call to inspect current values._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of the policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| scalarActive | struct PolicyStorage.PolicyScalar | The active scalar values for the policy. |

### policyRuleId

```solidity
function policyRuleId(uint32 policyId) external returns (bytes32 ruleId)
```

Inspect the policy ruleId.

_Use static call to inspect current values._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of the policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The active scalar values of the policy. |

### policyTtl

```solidity
function policyTtl(uint32 policyId) external returns (uint32 ttl)
```

Inspect the policy ttl.

_Use static call to inspect current values._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of the policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ttl | uint32 | The active ttl of the policy. |

### policyAllowApprovedCounterparties

```solidity
function policyAllowApprovedCounterparties(uint32 policyId) external returns (bool isAllowed)
```

Check if the policy allows counterparty approvals.

_Use static call to inspect current values._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The unique identifier of the policy. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isAllowed | bool | True if the active policy configuration allows counterparty approvals. |

### policyDisabled

```solidity
function policyDisabled(uint32 policyId) external view returns (bool isDisabled)
```

Inspect the policy disablement flag.

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policyId. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isDisabled | bool | True if the policy is disabled. |

### policyCanBeDisabled

```solidity
function policyCanBeDisabled(uint32 policyId) external returns (bool canIndeed)
```

A policy is deemed failed if all attestors or any wallet check has been
     degraded for a period exceeding the policyDisablementPeriod.

_Use static calls to inspect._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| canIndeed | bool | True if the policy can be disabled. |

### policyAttestorCount

```solidity
function policyAttestorCount(uint32 policyId) public returns (uint256 count)
```

Count the active policy attestors.

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

Inspect the active policy attestor at the index.

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

Inspect the full list of active policy attestors.

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

Check if an attestor is active for the policy.

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

Count the active wallet checks for the policy.

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The count of active wallet checks for the Policy. |

### policyWalletCheckAtIndex

```solidity
function policyWalletCheckAtIndex(uint32 policyId, uint256 index) external returns (address walletCheck)
```

Inspect the active wallet check at the index.

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

Inspect the full list of active wallet checks for the policy.

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

Check if a wallet check is active for the policy.

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

### policyBackdoorCount

```solidity
function policyBackdoorCount(uint32 policyId) external returns (uint256 count)
```

Count backdoors in a policy

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The count of backdoors in the policy. |

### policyBackdoorAtIndex

```solidity
function policyBackdoorAtIndex(uint32 policyId, uint256 index) external returns (bytes32 backdoorId)
```

Iterate the backdoors in a policy.

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |
| index | uint256 | The index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| backdoorId | bytes32 | The backdoor id at the index in the policy. |

### policyBackdoors

```solidity
function policyBackdoors(uint32 policyId) external returns (bytes32[] backdoors)
```

Inspect the full list of backdoors in a policy.

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| backdoors | bytes32[] | The full list of backdoors in effect for the policy. |

### isPolicyBackdoor

```solidity
function isPolicyBackdoor(uint32 policyId, bytes32 backdoorId) external returns (bool isIndeed)
```

Check if a backdoor is in a policy.

_Use static calls to inspect current information._

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| policyId | uint32 | The policy to inspect. |
| backdoorId | bytes32 | The backdoor id to check for. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the backdoor id is present in the policy. |

### policyCount

```solidity
function policyCount() public view returns (uint256 count)
```

Count the policies in the system.

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Existing policies in PolicyManager. |

### isPolicy

```solidity
function isPolicy(uint32 policyId) public view returns (bool isIndeed)
```

Check if a policyId exists in the system.

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

Count the global attestors admitted into the system.

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Total count of Attestors admitted to the global whitelist. |

### globalAttestorAtIndex

```solidity
function globalAttestorAtIndex(uint256 index) external view returns (address attestor)
```

Inspect the global attestor at the index.

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

Check if an address is admitted to the global attestors list.

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

Count wallet checks admitted to the global list.

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | Total count of wallet checks admitted to the global whitelist. |

### globalWalletCheckAtIndex

```solidity
function globalWalletCheckAtIndex(uint256 index) external view returns (address walletCheck)
```

Inspect the global wallet check at the index.

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

Check if an address is admitted to the global wallet check list.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| walletCheck | address | A wallet check contract address to search for. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the wallet check exists in the global whitelist, otherwise false. |

### globalBackdoorCount

```solidity
function globalBackdoorCount() external view returns (uint256 count)
```

Count backdoors that have been admitted into the system.

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The number of backdoors in the system. |

### globalBackdoorAtIndex

```solidity
function globalBackdoorAtIndex(uint256 index) external view returns (bytes32 backdoorId)
```

Iterate global backdoors.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| index | uint256 | The global backdoor index to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| backdoorId | bytes32 | The backdoorId at the index in the list of admitted backdoors. |

### isGlobalBackdoor

```solidity
function isGlobalBackdoor(bytes32 backdoorId) external view returns (bool isIndeed)
```

Check if a backdoorId exists in the global list of admitted backdoors.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| backdoorId | bytes32 | The backdoorId to check. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the backdoorId exists in the list of globally admitted backdoors. |

### backdoorPubKey

```solidity
function backdoorPubKey(bytes32 backdoorId) external view returns (uint256[2] pubKey)
```

Inspect backdoorPubKey associated with the backdoorId.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| backdoorId | bytes32 | The backdoorId to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| pubKey | uint256[2] | The backdoor public key. |

### attestorUri

```solidity
function attestorUri(address attestor) external view returns (string uri)
```

Inspect the Uri for an attestor on the global attestor list.

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

### minimumPolicyDisablementPeriod

```solidity
function minimumPolicyDisablementPeriod() external view returns (uint256 period)
```

Inspect the minimum policy disablement period.

_The minimum policy disablement period is the minimum time that must pass before a policy can be disabled._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| period | uint256 | The minimum policy disablement period. |

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

_Warning: This does not validate the inputs. Operands must be sorted ascending to be valid._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| ruleId | bytes32 | The ruleId that will be generated if the configuration is valid |

## KycERC20

This contract illustrates how an immutable KeyringGuard can be wrapped around collateral tokens 
 (e.g. DAI Token). Specify the token to wrap and the new name/symbol of the wrapped token - then good to go!
 Tokens can only be transferred to an address that maintains compliance with the configured policy.

### constructor

```solidity
constructor(struct IKeyringGuard.KeyringConfig config, uint32 policyId_, uint32 maximumConsentPeriod_, string name_, string symbol_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| config | struct IKeyringGuard.KeyringConfig | Keyring contract addresses. See IKycERC20. |
| policyId_ | uint32 | The unique identifier of a Policy. |
| maximumConsentPeriod_ | uint32 | The upper limit for user consent deadlines. |
| name_ | string | The name of the new wrapped token. Passed to ERC20.constructor to set the ERC20.name |
| symbol_ | string | The symbol for the new wrapped token. Passed to ERC20.constructor to set the ERC20.symbol |

### decimals

```solidity
function decimals() public view returns (uint8)
```

Returns decimals based on the underlying token decimals

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | uint8 | uint8 decimals integer |

### depositFor

```solidity
function depositFor(address trader, uint256 amount) public returns (bool)
```

Deposit underlying tokens and mint the same number of wrapped tokens.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | Recipient of the wrapped tokens |
| amount | uint256 | Quantity of underlying tokens from _msgSender() to exchange for wrapped tokens (to account) at 1:1 |

### withdrawTo

```solidity
function withdrawTo(address trader, uint256 amount) public returns (bool)
```

Burn a number of wrapped tokens and withdraw the same number of underlying tokens.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | Recipient of the underlying tokens |
| amount | uint256 | Quantity of wrapped tokens from _msgSender() to exchange for underlying tokens (to account) at 1:1 |

### transfer

```solidity
function transfer(address to, uint256 amount) public returns (bool)
```

Wraps the inherited ERC20.transfer function with the keyringCompliance guard.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| to | address | The recipient of amount |
| amount | uint256 | The amount to transfer. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool True if successfully executed. |

### transferFrom

```solidity
function transferFrom(address from, address to, uint256 amount) public returns (bool)
```

Wraps the inherited ERC20.transferFrom function with the keyringCompliance guard.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| from | address | The sender of amount |
| to | address | The recipient of amount |
| amount | uint256 | The amount to be deducted from the to's allowance. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | bool True if successfully executed. |

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

## UserPolicies

Users select one policy. Attestors are required to confirm compatibility of the user policy with
 the admission policy to check before issuing attestations. Traders may also define approves which are
 counterparties they will trade with even if compliance cannot be confirmed by an attestor. Approves
 only apply where admission policy owners have set the admission policy allowUserApproves flag to true.

### policyManager

```solidity
address policyManager
```

### userPolicies

```solidity
mapping(address => uint32) userPolicies
```

### constructor

```solidity
constructor(address trustedForwarder, address policyManager_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder | address | Contract address that is allowed to relay message signers. |
| policyManager_ | address |  |

### setUserPolicy

```solidity
function setUserPolicy(uint32 policyId) external
```

Users, normally auth wallets, set a policy to be checked by attestors.
     @param policyId The policy id to enable for the auth wallet.

### addApprovedCounterparty

```solidity
function addApprovedCounterparty(address approved) public
```

Trader wallets may appoint approved addresses to trade with without the protection
     of Keyring compliance checks. 
     @param approved A counterparty address to trade with unconditionally. Must not be approved.

### addApprovedCounterparties

```solidity
function addApprovedCounterparties(address[] approved) external
```

Trader wallets may appoint approved addresses to trade with without the protection
     of Keyring compliance checks. 
     @param approved Counterparty addresses to trade with unconditionally. Must not be approved.

### removeApprovedCounterparty

```solidity
function removeApprovedCounterparty(address approved) public
```

Trader wallets may appoint approved addresses to trade with without the protection
     of Keyring compliance checks.
     @param approved A counterparty to re-enable compliance checks. Must be approved.

### removeApprovedCounterparties

```solidity
function removeApprovedCounterparties(address[] approved) external
```

Trader wallets may appoint approved addresses to trade with without the protection
     of Keyring compliance checks. 
     @param approved Counterparty addresseses to re-enable compliance checks. Must be approved.

### approvedCounterpartyCount

```solidity
function approvedCounterpartyCount(address trader) external view returns (uint256 count)
```

Count the addresses on a trader approve.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The trader approve to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| count | uint256 | The number of addresses on a trader approve. |

### approvedCounterpartyAtIndex

```solidity
function approvedCounterpartyAtIndex(address trader, uint256 index) external view returns (address approved)
```

Iterate the addresses on a trader approve.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The trader approve to inspect. |
| index | uint256 | The row to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| approved | address | The address in the trader approve at the index row. |

### isApproved

```solidity
function isApproved(address trader, address counterparty) external view returns (bool isIndeed)
```

check if a counterparty is approved by a trader.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trader | address | The trader approve to inspect. |
| counterparty | address | The address to search for on the trader approve. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isIndeed | bool | True if the counterparty is present on the trader approve. |

## WalletCheck

Wallet checks are on-chain whitelists that can contain information gathered by
off-chain processes. Policies can specify which wallet checks must be checked on a just-in-time
basis. This contract establishes the interface that all wallet check contracts must implement. 
Future wallet check instances may employ additional logic. There is a distinct instance of a 
wallet check for each on-chain check.

### ROLE_WALLETCHECK_LIST_ADMIN

```solidity
bytes32 ROLE_WALLETCHECK_LIST_ADMIN
```

### ROLE_WALLETCHECK_META_ADMIN

```solidity
bytes32 ROLE_WALLETCHECK_META_ADMIN
```

### uri

```solidity
string uri
```

### onlyWalletCheckListAdmin

```solidity
modifier onlyWalletCheckListAdmin()
```

_Modifier to restrict access to functions to wallet check list admins only._

### onlyWalletCheckMetaAdmin

```solidity
modifier onlyWalletCheckMetaAdmin()
```

_Modifier to restrict access to functions to wallet check meta admins only._

### constructor

```solidity
constructor(address trustedForwarder_, address policyManager_, uint256 maximumConsentPeriod_, string uri_) public
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| trustedForwarder_ | address | Contract address that is allowed to relay message signers. |
| policyManager_ | address | The policy manager contract address. |
| maximumConsentPeriod_ | uint256 | The maximum allowable user consent period. |
| uri_ | string | The uri of the wallet check list. |

### updateUri

```solidity
function updateUri(string uri_) public
```

The wallet check admin can set the uri of the list maintained in this contract.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| uri_ | string | The new uri. |

### setWalletCheck

```solidity
function setWalletCheck(address wallet, bool whitelisted, uint256 timestamp) external
```

Record a wallet check.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| wallet | address | The subject wallet. |
| whitelisted | bool | True if the wallet has passed the checks represented by this contract. |
| timestamp | uint256 | The effective time of the wallet check. Not used if whitelisted is false. |

### checkWallet

```solidity
function checkWallet(address observer, address wallet, uint32 admissionPolicyId) external returns (bool passed)
```

Inspect the Wallet Check.

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| observer | address | The observer for degradation mitigation consent. |
| wallet | address | The wallet to inspect. |
| admissionPolicyId | uint32 | The admission policy for the wallet to inspect. |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| passed | bool | True if a wallet check exists or if mitigation measures are applicable. |

## AuthorizationVerifier

### verifyingKey

```solidity
function verifyingKey() internal pure returns (struct KeyringPairing.VerifyingKey vk)
```

## ConstructionVerifier

### verifyingKey

```solidity
function verifyingKey() internal pure returns (struct KeyringPairing.VerifyingKey vk)
```

## MembershipVerifier20

### verifyingKey

```solidity
function verifyingKey() internal pure returns (struct KeyringPairing.VerifyingKey vk)
```

## KeyringPairing

### InvalidProof

```solidity
error InvalidProof()
```

### VerifyingKey

```solidity
struct VerifyingKey {
  struct KeyringPairing.G1Point alfa1;
  struct KeyringPairing.G2Point beta2;
  struct KeyringPairing.G2Point gamma2;
  struct KeyringPairing.G2Point delta2;
  struct KeyringPairing.G1Point[] ic;
}
```

### Proof

```solidity
struct Proof {
  struct KeyringPairing.G1Point a;
  struct KeyringPairing.G2Point b;
  struct KeyringPairing.G1Point c;
}
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
  uint256 x;
  uint256 y;
}
```

### G2Point

```solidity
struct G2Point {
  uint256[2] x;
  uint256[2] y;
}
```

### negate

```solidity
function negate(struct KeyringPairing.G1Point p) internal pure returns (struct KeyringPairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct KeyringPairing.G1Point | The negation of p, i.e. p.addition(p.negate()) should be zero. |

### addition

```solidity
function addition(struct KeyringPairing.G1Point p1_, struct KeyringPairing.G1Point p2_) internal view returns (struct KeyringPairing.G1Point r)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct KeyringPairing.G1Point | The sum of two points of G1 |

### scalarMul

```solidity
function scalarMul(struct KeyringPairing.G1Point p, uint256 s) internal view returns (struct KeyringPairing.G1Point r)
```

_p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| r | struct KeyringPairing.G1Point | The product of a point on G1 and a scalar, i.e. |

### pairing

```solidity
function pairing(struct KeyringPairing.G1Point[] p1, struct KeyringPairing.G2Point[] p2) internal view returns (bool isValid)
```

Pairing check.

_e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
For example pairing([P1(), P1().negate()], [P2(), P2()]) should_

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isValid | bool | True if the proof passes the pairing check. |

## KeyringProofVerifier

### verifyingKey

```solidity
function verifyingKey() internal pure virtual returns (struct KeyringPairing.VerifyingKey vk)
```

### verify

```solidity
function verify(uint256[] input, struct KeyringPairing.Proof proof) internal view returns (bool)
```

_Verifies a Semaphore proof._

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| [0] | bool | isValid True if the proof is valid. |

### verifyProof

```solidity
function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[] input) public view returns (bool isValid)
```

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| isValid | bool | True if proof is valid |

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

