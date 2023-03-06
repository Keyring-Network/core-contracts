import { getNamedAccounts, ethers, upgrades } from "hardhat";
import { expect } from "chai";
import {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  KeyringZkCredentialUpdater,
  NoImplementation,
  KeyringZkVerifier,
  WalletCheck,
  IdentityTree,
  UserPolicies,
} from "../../src/types";
import { PolicyStorage } from "../../src/types/PolicyManager";
import {
  IdentityConstructionProofVerifier as _IdentityConstructionProofVerifier,
  AuthorizationProofVerifier as _AuthorizationProofVerifier,
  IdentityMembershipProofVerifier as _IdentityMembershipProofVerifier,
} from "../../src/typesHardcoded";
import IdentityConstructionProofVerifier from "../../artifacts/contracts/zkVerifiers/identityContructionProof/contracts/IdentityConstructionProofVerifier.sol/Verifier.json";
import AuthorizationProofVerifier from "../../artifacts/contracts/zkVerifiers/authorizationProof/contracts/AuthorizationProofVerifier.sol/Verifier.json";
import IdentityMembershipProofVerifier from "../../artifacts/contracts/zkVerifiers/membershipProof/contracts/IdentityMembershipProofVerifier.sol/Verifier20.json";
import { baseRules, genesis, ONE_DAY_IN_SECONDS, Operator, THIRTY_DAYS_IN_SECONDS } from "../../constants";

// silence hardhat-upgrades warnings
upgrades.silenceWarnings();

interface KeyringFixture {
  contracts: {
    credentials: KeyringCredentials;
    ruleRegistry: RuleRegistry;
    userPolicies: UserPolicies;
    policyManager: PolicyManager;
    credentialsUpdater: KeyringZkCredentialUpdater;
    forwarder: NoImplementation;
    identityConstructionProofVerifier: _IdentityConstructionProofVerifier;
    authorizationProofVerifier: _AuthorizationProofVerifier;
    identityMembershipProofVerifier: _IdentityMembershipProofVerifier;
    keyringZkVerifier: KeyringZkVerifier;
    walletCheck: WalletCheck;
    identityTree: IdentityTree;
  };
  policyScalar: PolicyStorage.PolicyScalarStruct;
}
export async function keyringTestFixture(): Promise<KeyringFixture> {
  const { admin, attestor1, attestor2 } = await getNamedAccounts();

  /* ------------------------------ Forwarder ------------------------------ */
  /**
   * A forwarder allows a relay to pay gas and forwards the message signer's address
   * to the contract which uses it in place of msg.sender using ERC2771Context.
   * This stateless contract is upgradeable.
   */

  const NoForwarder = await ethers.getContractFactory("NoImplementation");
  const forwarder = (await upgrades.deployProxy(NoForwarder, {
    unsafeAllow: ["constructor", "state-variable-immutable"],
  })) as NoImplementation;
  await forwarder.deployed();

  /* ---------------------------- KeyringZkVerifier --------------------------- */
  // first deploy the underlying verifier contracts
  const signer = ethers.provider.getSigner(admin);

  let verifierFactory = new ethers.ContractFactory(
    IdentityConstructionProofVerifier.abi,
    IdentityConstructionProofVerifier.bytecode,
    signer,
  );

  const identityConstructionProofVerifier = (await verifierFactory.deploy()) as _IdentityConstructionProofVerifier;
  await identityConstructionProofVerifier.deployed();

  verifierFactory = new ethers.ContractFactory(
    AuthorizationProofVerifier.abi,
    AuthorizationProofVerifier.bytecode,
    signer,
  );
  const authorizationProofVerifier = (await verifierFactory.deploy()) as _AuthorizationProofVerifier;
  await authorizationProofVerifier.deployed();

  verifierFactory = new ethers.ContractFactory(
    IdentityMembershipProofVerifier.abi,
    IdentityMembershipProofVerifier.bytecode,
    signer,
  );
  const identityMembershipProofVerifier = (await verifierFactory.deploy()) as _IdentityMembershipProofVerifier;
  await identityMembershipProofVerifier.deployed();

  // then deploy the zk credential updater
  const KeyringZkVerifierFactory = await ethers.getContractFactory("KeyringZkVerifier");
  const keyringZkVerifier = (await upgrades.deployProxy(KeyringZkVerifierFactory, {
    constructorArgs: [
      identityConstructionProofVerifier.address,
      identityMembershipProofVerifier.address,
      authorizationProofVerifier.address,
    ],
    unsafeAllow: ["constructor", "state-variable-immutable"],
  })) as KeyringZkVerifier;
  await keyringZkVerifier.deployed();

  /* ------------------------------ RuleRegistry ------------------------------ */
  /**
   * The rule registry holds the rule IDs incl. minimal metadata about base rules and formulas
   * for rules that are not base rules. This stateful contract is upgradeable.
   */
  const RuleRegistryFactory = await ethers.getContractFactory("RuleRegistry");
  const ruleRegistry = (await upgrades.deployProxy(RuleRegistryFactory, {
    constructorArgs: [forwarder.address],
    unsafeAllow: ["constructor", "delegatecall"],
  })) as RuleRegistry;
  await ruleRegistry.deployed();
  await ruleRegistry.init(genesis.universeDescription, genesis.universeUri, genesis.emptyDescription, genesis.emptyUri);

  /* ------------------------------ PolicyManager ----------------------------- */
  /**
   * The policy manager holds:
   * - a whitelist of Attestors admitted into the system by the global admin
   * - user-defined admission policies consisting of:
   *   - a rule
   *   - a minimum number of attestations required to qualify, called quorum
   *   - a time-to-live property that expires credentials
   * This stateful contract is upgradeable.
   */
  const PolicyStorageFactory = await ethers.getContractFactory("PolicyStorage");
  const PolicyStorage = await PolicyStorageFactory.deploy();
  await PolicyStorage.deployed();
  const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager", {
    libraries: {
      PolicyStorage: PolicyStorage.address,
    },
  });
  const policyManager = (await upgrades.deployProxy(PolicyManagerFactory, {
    constructorArgs: [forwarder.address, ruleRegistry.address],
    unsafeAllow: ["constructor", "delegatecall", "state-variable-immutable", "external-library-linking"],
  })) as PolicyManager;
  await policyManager.deployed();

  /* ------------------------------ UserPolicies ------------------------------ */

  const UserPoliciesFactory = await ethers.getContractFactory("UserPolicies");
  const userPolicies = (await upgrades.deployProxy(UserPoliciesFactory, {
    constructorArgs: [forwarder.address, policyManager.address],
    unsafeAllow: ["constructor"],
  })) as UserPolicies;
  await userPolicies.deployed();

  /* --------------------------- KeyringCredentials --------------------------- */
  /**
   * The credential credentials holds timestamps of user/policy credentials.
   * This stateful contract is upgradeable.
   */
  // NOTE policyManager.address is not required in the constructor
  const CredentialsFactory = await ethers.getContractFactory("KeyringCredentials");
  const credentials = (await upgrades.deployProxy(CredentialsFactory, {
    constructorArgs: [forwarder.address, policyManager.address],
    unsafeAllow: ["constructor", "delegatecall", "state-variable-immutable"],
  })) as KeyringCredentials;
  await credentials.deployed();
  await credentials.init();
  await policyManager.init();

  /* ---------------------- KeyringZkCredentialUpdater ----------------------- */
  /**
   * A credential updater can write to the credential credentials, contingent on permission.
   * The credential updater verifies signature packages submitted by users against the admission rule quorum, and
   * updates the credential credentials if a minimum number of acceptable signatures are presented.
   * This stateful contract is not upgradeable. It can be replaced by:
   *  - revoking write permission in the credentials contract
   *  - assigning write permission to a new credential updater
   *  - redirecting UI submissions to a replacement credential updater with write permission.
   */

  const CredentialsUpdaterFactory = await ethers.getContractFactory("KeyringZkCredentialUpdater");
  const credentialsUpdater = (await CredentialsUpdaterFactory.deploy(
    forwarder.address,
    credentials.address,
    policyManager.address,
    keyringZkVerifier.address,
  )) as KeyringZkCredentialUpdater;
  await credentialsUpdater.deployed();

  /* ------------------------------- WalletCheck ------------------------------ */
  const WalletCheck = await ethers.getContractFactory("WalletCheck");
  const walletCheck = (await WalletCheck.deploy(forwarder.address)) as WalletCheck;

  /* ------------------------------ IdentityTree ------------------------------ */
  const IdentityTree = await ethers.getContractFactory("IdentityTree");
  const identityTree = (await IdentityTree.deploy(forwarder.address)) as IdentityTree;

  /* ------------------------------ Grant Roles ------------------------------ */
  const credentialUpdaterRole = await credentials.ROLE_CREDENTIAL_UPDATER();
  const issuerAdminRole = await policyManager.ROLE_GLOBAL_ATTESTOR_ADMIN();
  const globalWalletCheckAdminRole = await policyManager.ROLE_GLOBAL_WALLETCHECK_ADMIN();
  const policyCreatorRole = await policyManager.ROLE_POLICY_CREATOR();
  const walletCheckAdminRole = await walletCheck.ROLE_WALLETCHECK_ADMIN();
  const roleAggregator = await identityTree.ROLE_AGGREGATOR();

  await credentials.grantRole(credentialUpdaterRole, credentialsUpdater.address);
  await policyManager.grantRole(issuerAdminRole, admin);
  await policyManager.grantRole(globalWalletCheckAdminRole, admin);
  await policyManager.grantRole(policyCreatorRole, admin);
  await walletCheck.grantRole(walletCheckAdminRole, admin);
  await walletCheck.grantRole(walletCheckAdminRole, credentialsUpdater.address);
  await identityTree.grantRole(roleAggregator, admin);
  await credentialsUpdater.grantRole(roleAggregator, admin);

  /* ------------------------------ Create Rules ------------------------------ */

  // creating six rules, three base rules and three expression rules (complement, union, intersection)
  // start by creating three base rules and retrieve ruleId's
  await ruleRegistry.createRule(...baseRules.PP_GB);
  await ruleRegistry.createRule(...baseRules.PP_US);
  await ruleRegistry.createRule(...baseRules.PEP);
  const RULE_ID_PP_GB = await ruleRegistry.ruleAtIndex(2);
  const RULE_ID_PP_US = await ruleRegistry.ruleAtIndex(3);
  const RULE_ID_PEP = await ruleRegistry.ruleAtIndex(4);

  // sorting ruleId's in acending order as required
  let sortedRules = sortAscendingOrder([RULE_ID_PP_GB, RULE_ID_PP_US]);

  // create two expression rules and retrieve ruleId's
  await ruleRegistry.createRule("", "", Operator.complement, [RULE_ID_PEP]);
  await ruleRegistry.createRule("", "", Operator.union, sortedRules);
  const RULE_ID_UNION_GB_US = await ruleRegistry.ruleAtIndex(5);
  const RULE_ID_COMPLEMENT_PEP = await ruleRegistry.ruleAtIndex(6);

  // create another expression rule based on the previous two rules
  sortedRules = sortAscendingOrder([RULE_ID_UNION_GB_US, RULE_ID_COMPLEMENT_PEP]);
  await ruleRegistry.createRule("", "", Operator.intersection, sortedRules);
  const RULE_ID_GBUS_EXCL_PEP = await ruleRegistry.ruleAtIndex(7);

  /* -------------------- Admit Attestors and Walletchecks -------------------- */

  // admit attestors to the global whitelist
  await policyManager.admitAttestor(attestor1, "https://one.attestor");
  await policyManager.admitAttestor(attestor2, "https://changeme.attestor");
  await policyManager.updateAttestorUri(attestor2, "https://two.attestor");
  expect(await policyManager.isGlobalAttestor(attestor1)).to.equal(true);
  expect(await policyManager.isGlobalAttestor(attestor2)).to.equal(true);
  await expect(policyManager.callStatic.globalAttestorAtIndex(3)).to.revertedWith("Unacceptable");
  expect(await policyManager.attestorUri(attestor1)).to.equal("https://one.attestor");
  expect(await policyManager.attestorUri(attestor2)).to.equal("https://two.attestor");

  await policyManager.admitAttestor(identityTree.address, "https://one.attestor");

  // admit walletcheck to the global whitelist
  await policyManager.admitWalletCheck(walletCheck.address);

  /* ------------------------------ Create Policy ----------------------------- */

  // create a first policy
  const policyId = 1;
  const policyScalar: PolicyStorage.PolicyScalarStruct = {
    ruleId: RULE_ID_GBUS_EXCL_PEP,
    descriptionUtf8: "Intersection: Union [ GB, US ], Complement [ PEP ] - 1 of 2",
    ttl: ONE_DAY_IN_SECONDS,
    gracePeriod: THIRTY_DAYS_IN_SECONDS,
    acceptRoots: 1,
    locked: false,
    allowUserWhitelists: false,
  };
  await policyManager.createPolicy(policyScalar, [attestor1, attestor2, identityTree.address], [walletCheck.address]);

  // check if the policy is created correctly
  expect(await policyManager.isPolicy(policyId)).to.equal(true);

  const policy = await policyManager.policyRawData(policyId);
  expect(policy.scalarActive.ruleId).to.equal(policyScalar.ruleId);
  expect(policy.scalarActive.descriptionUtf8).to.equal(policyScalar.descriptionUtf8);
  expect(policy.scalarActive.ttl).to.equal(policyScalar.ttl);
  expect(policy.scalarActive.gracePeriod).to.equal(policyScalar.gracePeriod);
  expect(policy.scalarActive.acceptRoots).to.equal(policyScalar.acceptRoots);
  expect(policy.scalarActive.locked).to.equal(policyScalar.locked);
  expect(policy.attestorsActive.length).to.equal(3);
  expect(policy.walletChecksActive.length).to.equal(1);
  expect(policy.attestorsActive.includes(attestor1)).to.equal(true);
  expect(policy.attestorsActive.includes(attestor2)).to.equal(true);
  expect(policy.deadline).to.equal(0);
  expect(
    policy.attestorsPendingAdditions.length +
      policy.attestorsPendingRemovals.length +
      policy.walletChecksPendingAdditions.length +
      policy.walletChecksPendingRemovals.length,
  ).to.equal(0);

  return {
    contracts: {
      credentials,
      ruleRegistry,
      userPolicies,
      policyManager,
      credentialsUpdater,
      forwarder,
      identityConstructionProofVerifier,
      authorizationProofVerifier,
      identityMembershipProofVerifier,
      keyringZkVerifier,
      walletCheck,
      identityTree,
    },
    policyScalar: policyScalar,
  };
}

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

function sortAscendingOrder(ruleIds: string[]) {
  return ruleIds.sort();
}
