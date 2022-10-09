import { createFixtureLoader } from "ethereum-waffle";
import { getNamedAccounts, ethers, waffle } from "hardhat";
import { expect } from "chai";

import type {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  KeyringV1CredentialUpdater,
  NoImplementation,
} from "../../src/types";

import { Operator, baseRules, namedAccounts, genesis, testPolicy } from "../../constants";
import { keyringTestFixture } from "../shared/fixtures";

const SEED_POLICY_OWNER = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("policy owner role seed"));
const ONE_DAY_IN_SECONDS = 24 * 60 * 60;
const ZERO_ADDRESS = ethers.constants.AddressZero;

/* -------------------------------------------------------------------------- */
/*  Test to enure rules and policies can be created and changed accordingly   */
/* -------------------------------------------------------------------------- */

describe("Admin", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];

  // prepare contracts with interfaces
  let credentials: KeyringCredentials;
  let ruleRegistry: RuleRegistry;
  let policyManager: PolicyManager;
  let credentialsUpdater: KeyringV1CredentialUpdater;
  let forwarder: NoImplementation;
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  before(async function () {
    // accounts in this test
    const { admin, alice, bob, verifier1, verifier2, attacker } = await getNamedAccounts();
    this.admin = admin;
    this.alice = alice;
    this.bob = bob;
    this.verifier1 = verifier1;
    this.verifier2 = verifier2;
    this.attacker = attacker;
    // `attacker` connect's with contract and try to sign invalid
    this.attackerAsSigner = ethers.provider.getSigner(attacker);
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  describe("Keyring Admin", function () {
    beforeEach(async function () {
      // load pre-configured contracts
      const fixture = await loadFixture(keyringTestFixture);
      credentials = fixture.credentials;
      ruleRegistry = fixture.ruleRegistry;
      policyManager = fixture.policyManager;
      credentialsUpdater = fixture.credentialsUpdater;
      forwarder = fixture.forwarder;

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

      // admit verifiers to the global whitelist
      await policyManager.admitVerifier(this.verifier1, "https://one.verifier");
      await policyManager.admitVerifier(this.verifier2, "https://changeme.verifier");

      await policyManager.updateVerifierUri(this.verifier2, "https://two.verifier");

      // create a first policy
      await policyManager.createPolicy(testPolicy.description, RULE_ID_GBUS_EXCL_PEP, ONE_DAY_IN_SECONDS);
      const policyId = await policyManager.policyAtIndex(0);
      const policyDescription = await policyManager.policyDescription(policyId);
      // setup a quorum of 1 out of 2 required verifiers
      // add two verifiers to the policy
      await policyManager.addPolicyVerifiers(policyId, [ this.verifier1, this.verifier2 ]);
      // set requiredVerifiers to one
      await policyManager.updatePolicy(policyId, testPolicy.description, RULE_ID_GBUS_EXCL_PEP, 1, ONE_DAY_IN_SECONDS);
      const policy = await policyManager.policy(policyId);
      expect(policy.description).to.equal(testPolicy.description);
      expect(policyDescription).to.equal(testPolicy.description);
      expect(policy.ruleId).to.equal(RULE_ID_GBUS_EXCL_PEP);
      expect(policy.requiredVerifiers.toString()).to.equal("1");
      expect(policy.expiryTime.toString()).to.equal(ONE_DAY_IN_SECONDS.toString());
    });

    it("should create a policy in a single step", async function () {
      const RULE_ID_GBUS_EXCL_PEP = await ruleRegistry.ruleAtIndex(7);
      const ruleId = await ruleRegistry.ruleAtIndex(0);
      const verifier1 = await policyManager.verifierAtIndex(0);
      const verifier2 = await policyManager.verifierAtIndex(1);
      await policyManager.createPolicyWithVerifiers(testPolicy.description, ruleId, ONE_DAY_IN_SECONDS, 1, [verifier1, verifier2]);
      const policyId = await policyManager.policyAtIndex(0);
      const policyDescription = await policyManager.policyDescription(policyId);
      const policy = await policyManager.policy(policyId);
      expect(policy.description).to.equal(testPolicy.description);
      expect(policyDescription).to.equal(testPolicy.description);
      expect(policy.ruleId).to.equal(RULE_ID_GBUS_EXCL_PEP);
      expect(policy.requiredVerifiers.toString()).to.equal("1");
      expect(policy.expiryTime.toString()).to.equal(ONE_DAY_IN_SECONDS.toString());
    });

    it("should be ready to test", async function () {
      expect(true).to.equal(true);
    });

    it("should configure, create rules, create policies and admit verifiers", async function () {
      // retrieve keyring admin roles
      const credentialsUpdaterRole = await credentials.roleCredentialsUpdater();
      const verifierAdminRole = await policyManager.roleGlobalVerifierAdmin();
      const ruleAdminRole = await ruleRegistry.roleRuleAdmin();

      // retrieve the ruleRegistry initial configuration
      const genesisRules = await ruleRegistry.genesis();
      const universeRule = await ruleRegistry.rule(genesisRules.universeRuleId);
      const emptyRule = await ruleRegistry.rule(genesisRules.emptyRuleId);
      const universeDescription = await ruleRegistry.ruleDescription(genesisRules.universeRuleId);
      const universeUri = await ruleRegistry.ruleUri(genesisRules.universeRuleId);
      const universeOperator = await ruleRegistry.ruleOperator(genesisRules.universeRuleId);
      const universeOperandCount = await ruleRegistry.ruleOperandCount(genesisRules.universeRuleId);

      // retrieve current counts of the entities
      const ruleCount = await ruleRegistry.ruleCount();
      const verifierCount = await policyManager.verifierCount();
      const verifier1 = await policyManager.verifierAtIndex(0);
      const verifier2 = await policyManager.verifierAtIndex(1);
      const policyCount = await policyManager.policyCount();
      const policyId = await policyManager.policyAtIndex(0);
      const policyDescription = await policyManager.policyDescription(policyId);

      // check if keyring admin roles are granted
      const updaterCanWrite = await credentials.hasRole(credentialsUpdaterRole, credentialsUpdater.address);
      const canAdminVerifiers = await policyManager.hasRole(verifierAdminRole, this.admin);
      const canAdminRules = await ruleRegistry.hasRole(ruleAdminRole, this.admin);

      // retrieve config of the KeyringV1CredentialUpdater
      const updaterPolicyManager = await credentialsUpdater.getPolicyManager();
      const updaterCredentials = await credentialsUpdater.getKeyringCredentials();

      // retrieve rule7 and states of the first policy
      const RULE_ID_GBUS_EXCL_PEP = await ruleRegistry.ruleAtIndex(7);
      const rule_gbus_excl_pep = await ruleRegistry.rule(RULE_ID_GBUS_EXCL_PEP);
      const rule_ggus_excl_pep_operand1 = await ruleRegistry.ruleOperandAtIndex(RULE_ID_GBUS_EXCL_PEP, 1);
      const policy = await policyManager.policy(policyId);
      const policyTimeout = await policyManager.policyExpiryTime(policyId);
      const policyRuleId = await policyManager.policyRuleId(policyId);
      const policyVerifier1 = await policyManager.policyVerifierAtIndex(policyId, 0);
      const policyVerifier2 = await policyManager.policyVerifierAtIndex(policyId, 1);
      const policyOwnerSeed = await policyManager.policyOwnerSeed();
      const verifier1Uri = await policyManager.verifierUri(this.verifier1);
      const verifier2Uri = await policyManager.verifierUri(this.verifier2);

      // check that the genesis rules were created correctly
      expect(universeRule.description).to.equal(genesis.universeDescription);
      expect(universeRule.uri).to.equal(genesis.universeUri);
      expect(universeRule.operator).to.equal(Operator.base);
      expect(universeRule.operandCount.toString()).to.equal("0");
      expect(emptyRule.description).to.equal(genesis.emptyDescription);
      expect(emptyRule.uri).to.equal(genesis.emptyUri);
      expect(emptyRule.operator).to.equal(Operator.base);
      expect(emptyRule.operandCount.toString()).to.equal("0");
      expect(universeDescription).to.equal(genesis.universeDescription);
      expect(universeUri).to.equal(genesis.universeUri);
      expect(universeOperator).to.equal(Operator.base);
      expect(universeOperandCount.toString()).to.equal("0");

      // check that the expression was created correctly
      expect(rule_gbus_excl_pep.operandCount.toString()).to.equal("2");
      expect(rule_ggus_excl_pep_operand1).to.equal(await ruleRegistry.ruleAtIndex(5));

      // check that the states changed accordingly
      expect(policyVerifier1).to.equal(this.verifier1);
      expect(policyVerifier2).to.equal(this.verifier2);
      expect(ruleCount.toString()).to.equal("8");
      expect(verifierCount.toString()).to.equal("2");
      expect(verifier1).to.equal(this.verifier1);
      expect(verifier2).to.equal(this.verifier2);
      expect(policyCount.toString()).to.equal("1");
      expect(updaterCanWrite).to.equal(true);
      expect(canAdminVerifiers).to.equal(true);
      expect(canAdminRules).to.equal(true);
      expect(updaterPolicyManager).to.equal(policyManager.address);
      expect(updaterCredentials).to.equal(credentials.address);
      expect(policy.description).to.equal(testPolicy.description);
      expect(policyDescription).to.equal(testPolicy.description);
      expect(policy.ruleId).to.equal(RULE_ID_GBUS_EXCL_PEP);
      expect(policy.requiredVerifiers.toString()).to.equal("1");
      expect(policy.expiryTime.toString()).to.equal(ONE_DAY_IN_SECONDS.toString());
      expect(policyRuleId).to.equal(RULE_ID_GBUS_EXCL_PEP);
      expect(policyTimeout.toString()).to.equal(ONE_DAY_IN_SECONDS.toString());
      expect(policyOwnerSeed).to.equal(SEED_POLICY_OWNER);
      expect(verifier1Uri).to.equal("https://one.verifier");
      expect(verifier2Uri).to.equal("https://two.verifier");
    });

    it("should not allow invalid rules", async function () {
      const bogusId = ethers.utils.keccak256(await ruleRegistry.ruleAtIndex(0));
      const getRule0 = await ruleRegistry.ruleAtIndex(0);
      const getRule1 = await ruleRegistry.ruleAtIndex(1);
      const getRule5 = await ruleRegistry.ruleAtIndex(5);
      let sortedRules = sortAscendingOrder([getRule0, getRule1]);

      await expect(ruleRegistry.updateRuleUri(bogusId, "https://no such rule")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "updateRuleUri",
          "ruleId not found"
        )
      );

      // uri cannot be empty
      await expect(ruleRegistry.updateRuleUri(getRule0, "")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "updateRuleUri",
          "uri cannot be empty"
        )
      );

      // not a base rule
      await expect(ruleRegistry.updateRuleUri(getRule5, "https://some-valid-complement")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "updateRuleUri",
          "not a base rule"
        )
      );

      // base rules cannot have operands
      await expect(ruleRegistry.createRule("description", "uri/", Operator.base, [getRule0])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "base rules cannot have operands"
        )
      );

      await expect(ruleRegistry.createRule(...baseRules.PP_GB)).to.be.revertedWith("SetConsistency");

      await expect(ruleRegistry.createRule("", "", Operator.complement, [])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "complement must have exactly one operand"
        )
      );

      await expect(ruleRegistry.createRule("", "", Operator.union, [])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "union must have two or more operands"
        )
      );

      await expect(ruleRegistry.createRule("", "", Operator.intersection, [])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "intersection must have two or more operands"
        )
      );

      await expect(
        ruleRegistry.createRule("description not allowed", "", Operator.intersection, sortedRules),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "only base rules can have a description"
        )
      );

      await expect(
        ruleRegistry.createRule("", "uri not allowed", Operator.intersection, sortedRules),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "only base rules can have a uri"
        )
      );

      await expect(ruleRegistry.createRule("", "http://canada.rule", Operator.base, [])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "base rules must have a description"
        )
      );

      await expect(ruleRegistry.createRule("canada", "", Operator.base, [])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "validateRule",
          "base rules must have a uri"
        )
      );

      sortedRules = sortAscendingOrder([bogusId, getRule0]);

      await expect(ruleRegistry.createRule("", "", Operator.intersection, sortedRules)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "createRule",
          "operand not found"
        )
      );

      await expect(ruleRegistry.createRule("", "", Operator.intersection, sortedRules.reverse())).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "createRule",
          "operands must be declared in ascending ruleId order"
        )
      );
    });

    it("should not allow an incomplete verifier record", async function () {
      await expect(policyManager.admitVerifier(this.verifier1, "")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "admitVerifier",
          "verifier uri cannot be empty"
        )
      );

      await expect(policyManager.updateVerifierUri(await policyManager.verifierAtIndex(0), "")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updateVerifierUri",
          "verifier uri cannot be empty"
        )
      );

      await expect(policyManager.updateVerifierUri(this.attacker, "attacked")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updateVerifierUri",
          "verifier not found"
        )
      );
    });

    it("should not allow invalid policy changes", async function () {
      const bogusId = ethers.utils.keccak256(await ruleRegistry.ruleAtIndex(0));
      const goodPolicyId = await policyManager.policyAtIndex(0);
      const goodRuleId = await ruleRegistry.ruleAtIndex(0);

      // check that invalid policy changes are not possible
      await expect(policyManager.createPolicy("", bogusId, ONE_DAY_IN_SECONDS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "createPolicy",
          "description cannot be empty"
        )
      );

      await expect(policyManager.createPolicy("bogus", bogusId, ONE_DAY_IN_SECONDS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "createPolicy",
          "ruleId not found"
        )
      );

      await expect(policyManager.updatePolicy(goodPolicyId, "", bogusId, 0, ONE_DAY_IN_SECONDS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyDescription",
          "description cannot be empty"
        )
      );

      await expect(
        policyManager.updatePolicy(goodPolicyId, "bogus", bogusId, 0, ONE_DAY_IN_SECONDS),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyRuleId",
          "ruleId not found"
        )
      );

      await expect(policyManager.updatePolicy(bogusId, "bogus", goodRuleId, 0, ONE_DAY_IN_SECONDS)).to.be.revertedWith(
        "Unauthorized",
      );

      await policyManager.grantRole(bogusId, this.admin);

      await expect(policyManager.updatePolicy(bogusId, "bogus", goodRuleId, 0, ONE_DAY_IN_SECONDS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyDescription",
          "policyId not found"
        )
      );

      await expect(
        policyManager.updatePolicy(goodPolicyId, "impossible", goodRuleId, 99, ONE_DAY_IN_SECONDS),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyRequiredVerifiers",
          "add verifiers first"
        )
      );

      await expect(policyManager.addPolicyVerifiers(goodPolicyId, [this.attacker])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "addPolicyVerifier",
          "verifier not found in the global list"
        )
      );

      await policyManager.admitVerifier(this.bob, "https://bob.verifier");

      await expect(policyManager.addPolicyVerifiers(bogusId, [this.bob])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "addPolicyVerifier",
          "policyId not found"
        )
      );

      await expect(policyManager.removePolicyVerifiers(bogusId, [this.bob])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "removePolicyVerifier",
          "policyId not found"
        )
      );

      await policyManager.updatePolicyRequiredVerifiers(goodPolicyId, 2);

      await expect(policyManager.removePolicyVerifiers(goodPolicyId, [this.verifier1])).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "removePolicyVerifier",
          "lower requiredVerifiers first"
        )
      );

      await expect(policyManager.admitVerifier(ZERO_ADDRESS, "uri/verifierZero")).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "admitVerifier",
          "verifier address cannot be empty"
        )
      );

      // updatePolicyRuleId policyId not found
      await expect(policyManager.updatePolicyRuleId(bogusId, goodRuleId)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyRuleId",
          "policyId not found"
        )
      );

      // updatePolicyRequiredVerifiers policyId not found
      await expect(policyManager.updatePolicyRequiredVerifiers(bogusId, 1)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyRequiredVerifiers",
          "policyId not found"
        )
      );

      // updatePolicyExpiryTime policyId not found
      await expect(policyManager.updatePolicyExpiryTime(bogusId, ONE_DAY_IN_SECONDS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "updatePolicyExpiryTime",
          "policyId not found"
        )
      );

      // removeVerifier - AddressConsistency exist
      await expect(policyManager.admitVerifier(this.verifier1, "https://one.verifier")).to.be.revertedWith(
        "AddressConsistency",
      );

      // removeVerifier - AddressConsistency does not exist
      await expect(policyManager.removeVerifier(this.admin)).to.be.revertedWith("AddressConsistency");
    });

    it("should not let unauthorized users create base rules", async function () {
      await expect(
        ruleRegistry.connect(this.attackerAsSigner).createRule("Bogus", "bogus", Operator.base, []),
      ).to.be.revertedWith("Unauthorized");
      const ruleCount = await ruleRegistry.ruleCount();
      expect(ruleCount.toString()).to.equal("8");
    });

    it("should not let unauthorized users modify policies", async function () {
      const policyId = await policyManager.policyAtIndex(0);
      const ruleId = await ruleRegistry.ruleAtIndex(0);

      await expect(
        policyManager.connect(this.attackerAsSigner).updatePolicy(policyId, "attacked", ruleId, 1, 999),
      ).to.be.revertedWith("Unauthorized");
    });

    it("should not allow unauthorized users admit verifiers", async function () {
      const verifierAdminRole = await policyManager.roleGlobalVerifierAdmin();

      await expect(
        policyManager.connect(this.attackerAsSigner).admitVerifier(this.attacker, "https://one.verifier"),
      ).to.be.revertedWith("Unauthorized");
      await expect(policyManager.connect(this.attackerAsSigner).removeVerifier(this.verifier1)).to.be.revertedWith(
        "Unauthorized",
      );

      await expect(
        policyManager.connect(this.attackerAsSigner).removeVerifier(await policyManager.verifierAtIndex(0)),
      ).to.be.revertedWith("Unauthorized");

      const verifierCount = await policyManager.verifierCount();
      expect(verifierCount.toString()).to.equal("2");
    });

    it("should not allow users to set an invalid policy", async function () {
      const bogusId = ethers.utils.keccak256(await ruleRegistry.ruleAtIndex(0));
      await expect(policyManager.setUserPolicy(bogusId)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "setUserPolicy",
          "policyId not found"
        )
      );
    });

    it("should allow policy owners to manage policy verifiers", async function () {
      const policyId = await policyManager.policyAtIndex(0);

      await expect(
        policyManager.connect(this.attackerAsSigner).addPolicyVerifiers(policyId, [this.attacker]),
      ).to.be.revertedWith("Unauthorized");

      await policyManager.removePolicyVerifiers(policyId, [this.verifier1]);

      const countAfterRemoval = await policyManager.policyVerifierCount(policyId);
      expect(countAfterRemoval.toString()).to.equal("1");
    });

    it("should allow users to set their policy", async function () {
      const policyId = await policyManager.policyAtIndex(0);
      await policyManager.setUserPolicy(policyId);
      const userPolicyId = await policyManager.userPolicy(this.admin);
      expect(userPolicyId).to.equal(policyId);
    });

    it("should emit a friendly message for policy row out of range", async function () {
      await expect(policyManager.policyAtIndex(99)).to.be.revertedWith("Unacceptable");
    });

    it("should allow the verifier admin to remove a verifier", async function () {
      await policyManager.removeVerifier(this.verifier1);
      const verifierCount = await policyManager.verifierCount();
      expect(verifierCount.toString()).to.equal("1");
    });

    it("should allow the ruleAdmin to update a rule uri", async function () {
      const ruleId = await ruleRegistry.ruleAtIndex(0);
      await ruleRegistry.updateRuleUri(ruleId, "https://new.uri");
      const rule = await ruleRegistry.rule(ruleId);
      expect(rule.uri).to.equal("https://new.uri");
    });

    it("should not deploy if constructor inputs are empty", async function () {
      const CredentialsFactory = await ethers.getContractFactory("KeyringCredentials");
      await expect(CredentialsFactory.deploy(ZERO_ADDRESS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringCredentials",
          "constructor",
          "trustedForwarder cannot be empty"
        )
      );

      const CredentialsUpdaterFactory = await ethers.getContractFactory("KeyringV1CredentialUpdater");
      await expect(
        CredentialsUpdaterFactory.deploy(ZERO_ADDRESS, credentials.address, policyManager.address),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "constructor",
          "trustedForwarder cannot be empty"
        )
      );
      await expect(
        CredentialsUpdaterFactory.deploy(forwarder.address, ZERO_ADDRESS, policyManager.address),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "constructor",
          "keyringCredentials cannot be empty"
        )
      );
      await expect(
        CredentialsUpdaterFactory.deploy(forwarder.address, credentials.address, ZERO_ADDRESS),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "constructor",
          "policyManager cannot be empty"
        )
      );

      const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager");
      await expect(PolicyManagerFactory.deploy(ZERO_ADDRESS, ruleRegistry.address)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "constructor",
          "trustedForwarder cannot be empty"
        )
      );
      await expect(PolicyManagerFactory.deploy(forwarder.address, ZERO_ADDRESS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "PolicyManager",
          "constructor",
          "ruleRegistryAddr cannot be empty"
        )
      );

      const RuleRegistryFactory = await ethers.getContractFactory("RuleRegistry");
      await expect(RuleRegistryFactory.deploy(ZERO_ADDRESS)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "constructor",
          "trustedForwarder cannot be empty"
        )
      )
    });

    it("should not allow to init if inputs are empty", async function () {
      const RuleRegistryFactory = await ethers.getContractFactory("RuleRegistry");
      const ruleRegistry = await RuleRegistryFactory.deploy(forwarder.address);
      
      // universeDescription cannot be empty
      await expect(
        ruleRegistry.init("", genesis.universeUri, genesis.emptyDescription, genesis.emptyUri),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "init",
          "universeDescription cannot be empty"
        )
      );
      
      // universeUri cannot be empty
      await expect(
        ruleRegistry.init(genesis.universeDescription, "", genesis.emptyDescription, genesis.emptyUri),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "init",
          "universeUri cannot be empty"
        )
      );

      // emptyDescription cannot be empty
      await expect(
        ruleRegistry.init(genesis.universeDescription, genesis.universeUri, "", genesis.emptyUri),
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "init",
          "emptyDescription cannot be empty"
        )
      );
  
      // emptyUri cannot be empty
      await expect(
        ruleRegistry.init(genesis.universeDescription, genesis.universeUri, genesis.emptyDescription, "")
      ).to.be.revertedWith(
        unacceptable(
          this.admin,
          "RuleRegistry",
          "init",
          "emptyUri cannot be empty"
        )
      );
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

function sortAscendingOrder(ruleIds: string[]) {
  return ruleIds.sort();
}

// function generates custom error message
const unacceptable = (sender: string, module: string, method: string, reason: string) => {
  return `Unacceptable("${sender}", "${module}", "${method}", "${reason}")`;
};
