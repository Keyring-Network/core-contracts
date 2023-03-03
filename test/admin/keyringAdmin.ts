import { Signer } from "ethers";
import { createFixtureLoader } from "ethereum-waffle";
import { getNamedAccounts, ethers, waffle } from "hardhat";
import { expect } from "chai";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import { keyringTestFixture } from "../shared/fixtures";
import type {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  NoImplementation,
  KeyringZkVerifier,
  WalletCheck,
  IdentityTree,
  UserPolicies,
} from "../../src/types";
import { PolicyStorage } from "../../src/types/PolicyManager";
import {
  Operator,
  namedAccounts,
  genesis,
  ONE_DAY_IN_SECONDS,
  ROLE_GLOBAL_ATTESTOR_ADMIN,
  ROLE_RULE_ADMIN,
  ROLE_WALLETCHECK_ADMIN,
  THIRTY_DAYS_IN_SECONDS,
  NULL_ADDRESS,
} from "../../constants";

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
  let userPolicies: UserPolicies;
  let policyManager: PolicyManager;
  let forwarder: NoImplementation;
  let keyringZkVerifier: KeyringZkVerifier;
  let walletCheck: WalletCheck;
  let identityTree: IdentityTree;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  // policy struct to be used in tests
  let policyScalar: PolicyStorage.PolicyScalarStruct;

  // accounts in this test
  let admin: string;
  let bob: string;
  let attestor1: string;
  let attestor2: string;
  let attacker: string;
  let attackerAsSigner: Signer;

  before(async () => {
    const {
      admin: adminAddress,
      bob: bobAddress,
      attestor1: attestor1Address,
      attestor2: attestor2Address,
      attacker: attackerAddress,
    } = await getNamedAccounts();
    admin = adminAddress;
    bob = bobAddress;
    attestor1 = attestor1Address;
    attestor2 = attestor2Address;
    // `attacker` connect's with contract and try to sign invalid
    attacker = attackerAddress;
    attackerAsSigner = ethers.provider.getSigner(attacker);
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  describe("Keyring Admin", function () {
    beforeEach(async function () {
      // load pre-configured contracts
      const fixture = await loadFixture(keyringTestFixture);
      credentials = fixture.contracts.credentials;
      ruleRegistry = fixture.contracts.ruleRegistry;
      userPolicies = fixture.contracts.userPolicies;
      policyManager = fixture.contracts.policyManager;
      forwarder = fixture.contracts.forwarder;
      keyringZkVerifier = fixture.contracts.keyringZkVerifier;
      walletCheck = fixture.contracts.walletCheck;
      identityTree = fixture.contracts.identityTree;

      policyScalar = fixture.policyScalar;
    });

    /* --------------------------------- GENERAL -------------------------------- */

    it("should not deploy if constructor inputs are empty", async function () {
      const CredentialsFactory = await ethers.getContractFactory("KeyringCredentials");
      await expect(CredentialsFactory.deploy(NULL_ADDRESS, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );
      await expect(CredentialsFactory.deploy(forwarder.address, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("policyManager_ cannot be empty"),
      );

      const CredentialsUpdaterFactory = await ethers.getContractFactory("KeyringZkCredentialUpdater");

      await expect(
        CredentialsUpdaterFactory.deploy(
          NULL_ADDRESS,
          credentials.address,
          policyManager.address,
          keyringZkVerifier.address,
        ),
      ).to.be.revertedWith(unacceptable("trustedForwarder cannot be empty"));
      await expect(
        CredentialsUpdaterFactory.deploy(
          forwarder.address,
          NULL_ADDRESS,
          policyManager.address,
          keyringZkVerifier.address,
        ),
      ).to.be.revertedWith(unacceptable("keyringCredentials cannot be empty"));
      await expect(
        CredentialsUpdaterFactory.deploy(
          forwarder.address,
          credentials.address,
          NULL_ADDRESS,
          keyringZkVerifier.address,
        ),
      ).to.be.revertedWith(unacceptable("policyManager cannot be empty"));
      await expect(
        CredentialsUpdaterFactory.deploy(forwarder.address, credentials.address, policyManager.address, NULL_ADDRESS),
      ).to.be.revertedWith(unacceptable("keyringZkVerifier cannot be empty"));

      const PolicyStorageFactory = await ethers.getContractFactory("PolicyStorage");
      const PolicyStorage = await PolicyStorageFactory.deploy();
      await PolicyStorage.deployed();
      const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager", {
        libraries: {
          PolicyStorage: PolicyStorage.address,
        },
      });
      await expect(PolicyManagerFactory.deploy(NULL_ADDRESS, ruleRegistry.address)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );
      await expect(PolicyManagerFactory.deploy(forwarder.address, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("ruleRegistry cannot be empty"),
      );

      const RuleRegistryFactory = await ethers.getContractFactory("RuleRegistry");
      await expect(RuleRegistryFactory.deploy(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );

      const UserPoliciesFactory = await ethers.getContractFactory("UserPolicies");
      await expect(UserPoliciesFactory.deploy(NULL_ADDRESS, policyManager.address)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );
      await expect(UserPoliciesFactory.deploy(forwarder.address, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("policyManager cannot be empty"),
      );

      const KeyringZkVerifierFactory = await ethers.getContractFactory("KeyringZkVerifier");
      const verifier = "0x0000000000000000000000000000000000000001";
      await expect(KeyringZkVerifierFactory.deploy(NULL_ADDRESS, verifier, verifier)).to.be.revertedWith(
        unacceptable("identityConstructionProofVerifier cannot be empty"),
      );
      await expect(KeyringZkVerifierFactory.deploy(verifier, NULL_ADDRESS, verifier)).to.be.revertedWith(
        unacceptable("membershipProofVerifier cannot be empty"),
      );
      await expect(KeyringZkVerifierFactory.deploy(verifier, verifier, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("authorisationProofVerifier cannot be empty"),
      );

      const WalletCheckFactory = await ethers.getContractFactory("WalletCheck");
      await expect(WalletCheckFactory.deploy(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );

      const IdentityTreeFactory = await ethers.getContractFactory("IdentityTree");
      await expect(IdentityTreeFactory.deploy(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );
    });

    it("should not allow to init if inputs are empty", async function () {
      const RuleRegistryFactory = await ethers.getContractFactory("RuleRegistry");
      const ruleRegistry = await RuleRegistryFactory.deploy(forwarder.address);

      // universeDescription cannot be empty
      await expect(
        ruleRegistry.init("", genesis.universeUri, genesis.emptyDescription, genesis.emptyUri),
      ).to.be.revertedWith(unacceptable("universeDescription cannot be empty"));

      // universeUri cannot be empty
      await expect(
        ruleRegistry.init(genesis.universeDescription, "", genesis.emptyDescription, genesis.emptyUri),
      ).to.be.revertedWith(unacceptable("universeUri cannot be empty"));

      // emptyDescription cannot be empty
      await expect(
        ruleRegistry.init(genesis.universeDescription, genesis.universeUri, "", genesis.emptyUri),
      ).to.be.revertedWith(unacceptable("emptyDescription cannot be empty"));

      // emptyUri cannot be empty
      await expect(
        ruleRegistry.init(genesis.universeDescription, genesis.universeUri, genesis.emptyDescription, ""),
      ).to.be.revertedWith(unacceptable("emptyUri cannot be empty"));
    });

    /* ------------------------------ PolicyManager ----------------------------- */

    it("should process staged changes and commit them if the deadline has passed", async () => {
      const policyId = 1;
      let now = await helpers.time.latest();
      const timeToNextBlock = 1; // 1 second, because the next block is happening 1 second after now
      let deadline = now + THIRTY_DAYS_IN_SECONDS + timeToNextBlock;

      // remove the second attestors from the policy
      await policyManager.removePolicyAttestors(policyId, [attestor2], deadline);

      const policyScalarUpdated = {
        ...policyScalar,
        ttl: ONE_DAY_IN_SECONDS * 2,
        acceptRoots: 0,
      };
      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + timeToNextBlock;

      await policyManager.updatePolicyScalar(policyId, policyScalarUpdated, deadline);

      // check if the staged changes are correct
      const policy = await policyManager.policyRawData(policyId);
      expect(policy.scalarPending.ttl).to.equal(policyScalarUpdated.ttl);
      expect(policy.scalarPending.acceptRoots).to.equal(policyScalarUpdated.acceptRoots);
      expect(policy.attestorsPendingRemovals.includes(attestor2)).to.equal(true);

      // check that the active policy is not changed
      expect(policy.scalarActive.ttl).to.equal(policyScalar.ttl);
      expect(policy.scalarActive.acceptRoots).to.equal(policyScalar.acceptRoots);
      expect(policy.attestorsActive.includes(attestor2)).to.equal(true);

      // move the time forward to the deadline and process the staged changes
      const policyDeadline = await policyManager.callStatic.policyDeadline(policyId);
      await helpers.time.increaseTo(policyDeadline);
      await policyManager.policy(policyId);

      // check if the staged changes are committed
      const policyAfterDeadline = await policyManager.policyRawData(policyId);
      expect(policyAfterDeadline.attestorsPendingRemovals.length).to.equal(0);
      expect(policyAfterDeadline.scalarActive.ttl).to.equal(policyScalarUpdated.ttl);
      expect(policyAfterDeadline.scalarActive.acceptRoots).to.equal(policyScalarUpdated.acceptRoots);
      expect(policyAfterDeadline.attestorsActive.includes(attestor2)).to.equal(false);

      // check the rule registry
      const ruleCount = await ruleRegistry.ruleCount();
      expect(ruleCount.toString()).to.equal("8");
    });

    it("should not allow invalid attestor records", async function () {
      await expect(policyManager.admitAttestor(NULL_ADDRESS, "address empty")).to.be.revertedWith(
        unacceptable("attestor cannot be empty"),
      );
      await expect(policyManager.admitAttestor(bob, "")).to.be.revertedWith(unacceptable("uri cannot be empty"));
      await expect(policyManager.updateAttestorUri(attestor1, "")).to.be.revertedWith(
        unacceptable("uri cannot be empty"),
      );
      await expect(policyManager.updateAttestorUri(bob, "attestor-does-not-exists")).to.be.revertedWith(
        unacceptable("attestor not found"),
      );

      await expect(policyManager.connect(attackerAsSigner).updateAttestorUri(attacker, "attacked")).to.be.revertedWith(
        unauthorized(
          attacker,
          "KeyringAccessControl",
          "_checkRole",
          ROLE_GLOBAL_ATTESTOR_ADMIN,
          "sender does not have the required role",
          "pm:oaa",
        ),
      );
    });

    it("should not allow to create invalid policies", async function () {
      const bogusRuleId = ethers.utils.keccak256(await ruleRegistry.ruleAtIndex(0));

      let invalidPolicyScalar: PolicyStorage.PolicyScalarStruct = {
        ...policyScalar,
        descriptionUtf8: "",
      };

      await expect(policyManager.createPolicy(invalidPolicyScalar, [], [])).to.be.revertedWith(
        unacceptable("descriptionUtf8 cannot be empty"),
      );

      invalidPolicyScalar = {
        ...policyScalar,
        ruleId: bogusRuleId,
      };

      await expect(policyManager.createPolicy(invalidPolicyScalar, [], [])).to.be.revertedWith(
        unacceptable("rule not found"),
      );
      await expect(policyManager.createPolicy(policyScalar, [bob], [])).to.be.revertedWith(
        unacceptable("attestor not found"),
      );
      await expect(policyManager.createPolicy(policyScalar, [], [bob])).to.be.revertedWith(
        unacceptable("walletCheck not found"),
      );
    });

    it("should not allow invalid policy changes", async function () {
      const bogusRuleId = ethers.utils.keccak256(await ruleRegistry.ruleAtIndex(0));
      const bogusPolicyId = 99;
      const bogusRole = ethers.utils.hexZeroPad(ethers.utils.hexlify(bogusPolicyId), 32);
      const validPolicyId = 1;
      const deadline = 0;

      const invalidPolicyScalar: PolicyStorage.PolicyScalarStruct = {
        ...policyScalar,
        descriptionUtf8: "",
      };

      await expect(policyManager.updatePolicyScalar(validPolicyId, invalidPolicyScalar, deadline)).to.be.revertedWith(
        unacceptable("descriptionUtf8 cannot be empty"),
      );

      await expect(policyManager.updatePolicyScalar(bogusPolicyId, invalidPolicyScalar, deadline)).to.be.revertedWith(
        unauthorized(
          admin,
          "KeyringAccessControl",
          "_checkRole",
          bogusRole,
          "sender does not have the required role",
          "pm:opa",
        ),
      );

      await expect(policyManager.updatePolicyRuleId(validPolicyId, bogusRuleId, deadline)).to.be.revertedWith(
        unacceptable("rule not found"),
      );

      await expect(policyManager.updatePolicyGracePeriod(validPolicyId, THIRTY_DAYS_IN_SECONDS, deadline)).to.be.not
        .reverted;

      let now = await helpers.time.latest();
      const invalidDeadline = now + THIRTY_DAYS_IN_SECONDS - 1;

      await expect(policyManager.setDeadline(validPolicyId, invalidDeadline)).to.be.revertedWith(
        unacceptable("deadline in the past or too soon"),
      );

      // attestor is not whitelisted
      await expect(policyManager.addPolicyAttestors(validPolicyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("attestor not found"),
      );
      // attestor exists already on the active list
      await expect(policyManager.addPolicyAttestors(validPolicyId, [attestor1], deadline)).to.be.revertedWith(
        unacceptable("attestor already in policy"),
      );
      // attestor exists already on the pending list
      await policyManager.admitAttestor(bob, "bob");
      await policyManager.addPolicyAttestors(validPolicyId, [bob], deadline);
      let policyData = await policyManager.policyRawData(validPolicyId);
      expect(policyData.attestorsPendingAdditions).to.have.members([bob]);
      await expect(policyManager.addPolicyAttestors(validPolicyId, [bob], deadline)).to.be.revertedWith(
        `AddressSetConsistency("AddressSet", "insert", "exists", "PolicyStorage:_writeAttestorAddition")`,
      );

      // add attestor to policy, add it to pending removals, remove it from pending removals
      now = await helpers.time.latest();
      let validDeadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.setDeadline(validPolicyId, validDeadline);
      await helpers.time.increaseTo(validDeadline);
      await policyManager.policy(validPolicyId);
      policyData = await policyManager.policyRawData(validPolicyId);
      expect(policyData.attestorsActive).to.have.members([attestor1, attestor2, identityTree.address, bob]);
      await policyManager.removePolicyAttestors(validPolicyId, [bob], deadline);
      await policyManager.addPolicyAttestors(validPolicyId, [bob], deadline);

      // remove attestor from policy, try it again
      now = await helpers.time.latest();
      validDeadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.removePolicyAttestors(validPolicyId, [bob], validDeadline);
      await helpers.time.increaseTo(validDeadline);
      await policyManager.policy(validPolicyId);
      policyData = await policyManager.policyRawData(validPolicyId);
      expect(policyData.attestorsPendingRemovals.length).to.equal(0);
      await expect(policyManager.removePolicyAttestors(validPolicyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("attestor not found"),
      );

      // remove attestor from pending additions and remove it again
      await policyManager.addPolicyAttestors(validPolicyId, [bob], deadline);
      await policyManager.removePolicyAttestors(validPolicyId, [bob], deadline);

      await policyManager.removeAttestor(bob);
      await expect(policyManager.removeAttestor(bob)).to.be.revertedWith("AddressSetConsistency");
    });

    it("should not let unauthorized users modify policies", async function () {
      const policyId = 0;
      const ruleId = await ruleRegistry.ruleAtIndex(0);
      const deadline = 0;

      policyScalar = {
        ...policyScalar,
        ruleId,
      };

      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyScalar(policyId, policyScalar, deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyRuleId(policyId, ruleId, deadline),
      ).to.be.revertedWith("Unauthorized");

      await expect(
        policyManager
          .connect(attackerAsSigner)
          .updatePolicyDescription(policyId, policyScalar.descriptionUtf8, deadline),
      ).to.be.revertedWith("Unauthorized");

      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyTtl(policyId, policyScalar.ttl, deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyGracePeriod(policyId, policyScalar.gracePeriod, deadline),
      ).to.be.revertedWith("Unauthorized");

      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyAcceptRoots(policyId, policyScalar.acceptRoots, deadline),
      ).to.be.revertedWith("Unauthorized");

      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyLock(policyId, true, deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(
        policyManager.connect(attackerAsSigner).updatePolicyLock(policyId, false, deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(policyManager.connect(attackerAsSigner).setDeadline(policyId, deadline)).to.be.revertedWith(
        "Unauthorized",
      );
      await expect(
        policyManager.connect(attackerAsSigner).addPolicyAttestors(policyId, [bob], deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(
        policyManager.connect(attackerAsSigner).removePolicyAttestors(policyId, [attestor1], deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(
        policyManager.connect(attackerAsSigner).addPolicyWalletChecks(policyId, [bob], deadline),
      ).to.be.revertedWith("Unauthorized");
      await expect(
        policyManager.connect(attackerAsSigner).removePolicyWalletChecks(policyId, [bob], deadline),
      ).to.be.revertedWith("Unauthorized");
    });

    it("should not allow unauthorized users admit attestors", async function () {
      await expect(
        policyManager.connect(attackerAsSigner).admitAttestor(attacker, "https://attacker.com"),
      ).to.be.revertedWith("Unauthorized");
      await expect(policyManager.connect(attackerAsSigner).removeAttestor(attestor1)).to.be.revertedWith(
        "Unauthorized",
      );
      await expect(
        policyManager.connect(attackerAsSigner).removeAttestor(await policyManager.globalAttestorAtIndex(0)),
      ).to.be.revertedWith("Unauthorized");

      const attestorCount = await policyManager.globalAttestorCount();
      expect(attestorCount.toNumber()).to.equal(3);
    });

    it("should not allow unauthorized users admit wallet checks", async function () {
      await expect(policyManager.connect(attackerAsSigner).admitWalletCheck(attacker)).to.be.revertedWith(
        "Unauthorized",
      );
      await expect(policyManager.connect(attackerAsSigner).removeWalletCheck(attestor1)).to.be.revertedWith(
        "Unauthorized",
      );
      await expect(
        policyManager.connect(attackerAsSigner).removeWalletCheck(await policyManager.globalWalletCheckAtIndex(0)),
      ).to.be.revertedWith("Unauthorized");

      const wc = await policyManager.globalWalletCheckAtIndex(0);
      const isWc = await policyManager.isGlobalWalletCheck(walletCheck.address);
      const isNotWc = await policyManager.isGlobalWalletCheck(admin);
      const walletCheckCount = await policyManager.globalWalletCheckCount();
      expect(wc).to.equal(walletCheck.address);
      expect(isWc).to.equal(true);
      expect(isNotWc).to.equal(false);
      expect(walletCheckCount.toNumber()).to.equal(1);
    });

    it("should allow an admin to remove a wallet check", async function () {
      await policyManager.removeWalletCheck(walletCheck.address);
      const walletCheckCount = await policyManager.globalWalletCheckCount();
      expect(walletCheckCount.toNumber()).to.equal(0);
    });

    it("should not allow users to set an invalid policy", async function () {
      const bogusId = await policyManager.policyCount();
      await expect(userPolicies.setUserPolicy(bogusId)).to.be.revertedWith(unacceptable("policyId not found"));
    });

    it("should allow users to set their policy", async function () {
      const policyId = 1;
      await userPolicies.setUserPolicy(policyId);
      const userPolicyId = await userPolicies.userPolicies(admin);
      expect(userPolicyId).to.equal(policyId);
    });

    it("should allow policy owners to manage policy attestors", async function () {
      const policyId = 1;

      let attestorCount = await policyManager.callStatic.policyAttestorCount(policyId);
      expect(attestorCount.toNumber()).to.equal(3);

      let policy = await policyManager.policyRawData(policyId);
      expect(
        policy.attestorsActive.length +
          policy.attestorsPendingAdditions.length +
          policy.attestorsPendingRemovals.length,
      ).to.equal(3);

      let deadline = 0;
      await policyManager.removePolicyAttestors(policyId, [attestor1], deadline);
      await policyManager.admitAttestor(bob, "https://bob.com");
      const now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.addPolicyAttestors(policyId, [bob], deadline);

      await helpers.time.increaseTo(deadline);
      await policyManager.policy(policyId);
      attestorCount = await policyManager.callStatic.policyAttestorCount(policyId);
      policy = await policyManager.policyRawData(policyId);

      expect(attestorCount.toNumber()).to.equal(3);
      expect(
        policy.attestorsActive.length +
          policy.attestorsPendingAdditions.length +
          policy.attestorsPendingRemovals.length,
      ).to.equal(3);
    });

    it("should allow policy owners to manage policy wallet checks", async function () {
      const policyId = 1;

      let walletCheckCount = await policyManager.callStatic.policyWalletCheckCount(policyId);
      expect(walletCheckCount.toNumber()).to.equal(1);
      await expect(policyManager.callStatic.policyWalletCheckAtIndex(policyId, walletCheckCount)).to.be.revertedWith(
        "index",
      );

      let policy = await policyManager.policyRawData(policyId);
      expect(
        policy.walletChecksActive.length +
          policy.walletChecksPendingAdditions.length +
          policy.walletChecksPendingRemovals.length,
      ).to.equal(1);

      let deadline = 0;
      await policyManager.removePolicyWalletChecks(policyId, [walletCheck.address], deadline);
      await policyManager.admitWalletCheck(bob);
      let now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.addPolicyWalletChecks(policyId, [bob], deadline);

      await helpers.time.increaseTo(deadline);
      await policyManager.policy(policyId);
      walletCheckCount = await policyManager.callStatic.policyWalletCheckCount(policyId);
      policy = await policyManager.policyRawData(policyId);

      expect(walletCheckCount.toNumber()).to.equal(1);
      expect(
        policy.walletChecksActive.length +
          policy.walletChecksPendingAdditions.length +
          policy.walletChecksPendingRemovals.length,
      ).to.equal(1);

      const policyWalletChecks = await policyManager.callStatic.policyWalletChecks(policyId);
      const policyWc1 = await policyManager.callStatic.policyWalletCheckAtIndex(policyId, 0);
      const ipwc = await policyManager.callStatic.isPolicyWalletCheck(policyId, bob);

      expect(policyWalletChecks).to.have.members([bob]);
      expect(policyWalletChecks.length).to.equal(1);
      expect(policyWc1).to.equal(bob);
      expect(ipwc).to.equal(true);

      // add walletcheck1 back, add it to pending removals, then remove it from pending removals
      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.addPolicyWalletChecks(policyId, [walletCheck.address], deadline);
      await policyManager.policy(policyId);
      deadline = 0;
      await policyManager.removePolicyWalletChecks(policyId, [walletCheck.address], deadline);
      await policyManager.addPolicyWalletChecks(policyId, [walletCheck.address], deadline);

      const globalWalletCheckCount = await policyManager.callStatic.globalWalletCheckCount();
      await expect(policyManager.callStatic.globalWalletCheckAtIndex(globalWalletCheckCount)).to.be.revertedWith(
        "index",
      );
      await policyManager.globalWalletCheckAtIndex(globalWalletCheckCount.toNumber() - 1);
    });

    it("should not allow invalid additions or removals of walletchecks", async function () {
      const policyId = 1;
      let deadline = 0;

      // try to add walletcheck to policy that does not was admitted
      await expect(policyManager.addPolicyWalletChecks(policyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("walletCheck not found"),
      );

      // try to add walletcheck to policy which is already on pending additions list
      await expect(policyManager.admitWalletCheck(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("walletCheck cannot be empty"),
      );
      await policyManager.admitWalletCheck(bob);
      await policyManager.addPolicyWalletChecks(policyId, [bob], deadline);
      let policyData = await policyManager.policyRawData(policyId);
      expect(policyData.walletChecksPendingAdditions).to.have.members([bob]);
      await expect(policyManager.addPolicyWalletChecks(policyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("walletCheck addition already scheduled"),
      );

      let now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.setDeadline(policyId, deadline);
      await helpers.time.increaseTo(deadline);
      await policyManager.policy(policyId);
      deadline = 0;
      policyData = await policyManager.policyRawData(policyId);
      expect(policyData.walletChecksActive).to.have.members([walletCheck.address, bob]);
      await expect(policyManager.addPolicyWalletChecks(policyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("walletCheck already in policy"),
      );

      // remove walletcheck from policy
      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.removePolicyWalletChecks(policyId, [bob], deadline);

      // try to remove again the walletcheck which is pending
      policyData = await policyManager.policyRawData(policyId);
      expect(policyData.walletChecksPendingRemovals).to.have.members([bob]);
      await expect(policyManager.removePolicyWalletChecks(policyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("walletCheck removal already scheduled"),
      );

      await helpers.time.increaseTo(deadline);
      await policyManager.policy(policyId);

      // try to remove, does not exist on active list
      deadline = 0;
      policyData = await policyManager.policyRawData(policyId);
      expect(policyData.walletChecksActive).to.have.members([walletCheck.address]);
      expect(policyData.walletChecksPendingAdditions).to.have.members([]);
      await expect(policyManager.removePolicyWalletChecks(policyId, [bob], deadline)).to.be.revertedWith(
        unacceptable("walletCheck is not in policy"),
      );
    });

    it("should allow the attestor admin to remove a attestor", async function () {
      await policyManager.removeAttestor(attestor1);
      const attestorCount = await policyManager.globalAttestorCount();
      expect(attestorCount.toNumber()).to.equal(2);
    });

    it("should allow policy admin to update the policy", async function () {
      const policy = 1;
      let deadline = 0;
      const RULE_UNIVERSE = await ruleRegistry.ruleAtIndex(0);

      const policyScalarUpdated = {
        ruleId: RULE_UNIVERSE,
        descriptionUtf8: "Updated description",
        ttl: ONE_DAY_IN_SECONDS * 2,
        gracePeriod: THIRTY_DAYS_IN_SECONDS,
        acceptRoots: 100,
        locked: true,
      };

      await policyManager.updatePolicyRuleId(policy, policyScalarUpdated.ruleId, deadline);
      await policyManager.updatePolicyDescription(policy, policyScalarUpdated.descriptionUtf8, deadline);
      await policyManager.updatePolicyTtl(policy, policyScalarUpdated.ttl, deadline);
      await policyManager.updatePolicyAcceptRoots(policy, policyScalarUpdated.acceptRoots, deadline);
      await policyManager.updatePolicyLock(policy, true, deadline);
      await policyManager.updatePolicyLock(policy, true, deadline); // to reach the empty else path
      await policyManager.updatePolicyLock(policy, false, deadline);
      await policyManager.updatePolicyLock(policy, false, deadline); // to reach the empty else path
      await policyManager.updatePolicyLock(policy, true, deadline);

      const now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 1;
      await policyManager.setDeadline(policy, deadline);

      await helpers.time.increaseTo(deadline);
      await policyManager.policy(policy);

      const policyUpdated = await policyManager.policyRawData(policy);

      expect(policyUpdated.scalarActive.ruleId).to.equal(policyScalarUpdated.ruleId);
      expect(policyUpdated.scalarActive.descriptionUtf8).to.equal(policyScalarUpdated.descriptionUtf8);
      expect(policyUpdated.scalarActive.ttl).to.equal(policyScalarUpdated.ttl);
      expect(policyUpdated.scalarActive.gracePeriod).to.equal(policyScalarUpdated.gracePeriod);
      expect(policyUpdated.scalarActive.acceptRoots).to.equal(policyScalarUpdated.acceptRoots);
      expect(policyUpdated.scalarActive.locked).to.equal(policyScalarUpdated.locked);
    });

    it("should not allow policy admin to update the locked policy", async function () {
      const policy = 1;
      const now = await helpers.time.latest();
      let deadline = now + THIRTY_DAYS_IN_SECONDS + 10;

      await policyManager.updatePolicyLock(policy, true, deadline);

      await helpers.time.increaseTo(deadline);
      await policyManager.policy(policy);

      const policyUpdated = await policyManager.policyRawData(policy);
      expect(policyUpdated.scalarActive.locked).to.equal(true);

      deadline = 0;
      await expect(policyManager.updatePolicyScalar(policy, policyScalar, deadline)).to.be.revertedWith(
        unacceptable("policy is locked"),
      );
      await expect(policyManager.updatePolicyRuleId(policy, policyScalar.ruleId, deadline)).to.be.revertedWith(
        unacceptable("policy is locked"),
      );
      await expect(
        policyManager.updatePolicyDescription(policy, policyScalar.descriptionUtf8, deadline),
      ).to.be.revertedWith(unacceptable("policy is locked"));
      await expect(policyManager.updatePolicyTtl(policy, policyScalar.ttl, deadline)).to.be.revertedWith(
        unacceptable("policy is locked"),
      );
      await expect(
        policyManager.updatePolicyAcceptRoots(policy, policyScalar.acceptRoots, deadline),
      ).to.be.revertedWith(unacceptable("policy is locked"));
      await expect(policyManager.updatePolicyLock(policy, false, deadline)).to.be.revertedWith(
        unacceptable("policy is locked"),
      );

      await expect(policyManager.removePolicyAttestors(policy, [attestor1], deadline)).to.be.revertedWith(
        unacceptable("policy is locked"),
      );
      await policyManager.admitAttestor(bob, "https://bob.com");
      await expect(policyManager.addPolicyAttestors(policy, [bob], deadline)).to.be.revertedWith(
        unacceptable("policy is locked"),
      );
    });

    it("should allow to inspect a policy", async function () {
      const policy = 1;

      const policyRuleId = await policyManager.callStatic.policyRuleId(policy);
      const policyDescription = await policyManager.callStatic.policyDescription(policy);
      const policyTtl = await policyManager.callStatic.policyTtl(policy);
      const policyGracePeriod = await policyManager.callStatic.policyGracePeriod(policy);
      const policyAcceptRoots = await policyManager.callStatic.policyAcceptRoots(policy);
      const policyLocked = await policyManager.callStatic.policyLocked(policy);

      expect(policyRuleId).to.equal(policyScalar.ruleId);
      expect(policyDescription).to.equal(policyScalar.descriptionUtf8);
      expect(policyTtl).to.equal(policyScalar.ttl);
      expect(policyGracePeriod).to.equal(policyScalar.gracePeriod);
      expect(policyAcceptRoots).to.equal(policyScalar.acceptRoots);
      expect(policyLocked).to.equal(false);

      const policyAttestors = await policyManager.callStatic.policyAttestors(policy);
      const policyAttestorAtIndex0 = await policyManager.callStatic.policyAttestorAtIndex(policy, 0);
      const policyAttestorAtIndex1 = await policyManager.callStatic.policyAttestorAtIndex(policy, 1);
      const attestorCount = await policyManager.callStatic.policyAttestorCount(policy);

      expect(attestorCount.toNumber()).to.equal(policyAttestors.length);
      expect(await policyManager.callStatic.isPolicyAttestor(policy, policyAttestorAtIndex0)).to.equal(true);
      expect(await policyManager.callStatic.isPolicyAttestor(policy, policyAttestorAtIndex1)).to.equal(true);
      expect(await policyManager.callStatic.isPolicyAttestor(policy, bob)).to.equal(false);
      await expect(policyManager.callStatic.policyAttestorAtIndex(policy, policyAttestors.length)).to.be.revertedWith(
        "index",
      );
    });

    it("should not allow ttl greater than max ttl", async function () {
      const MAX_TTL = 100 * 24 * 60 * 60 * 365; // 100 years
      await expect(policyManager.updatePolicyTtl(1, MAX_TTL + 1, 0)).to.be.revertedWith(
        unacceptable("ttl exceeds maximum duration"),
      );
      await policyManager.updatePolicyTtl(1, MAX_TTL, 0);
    });

    /* NOTE not feasible to test this
    it("should not allow to exceed the amount of max policies", async function () {
      const MAX_POLICIES = 2 ** 20 ;
    });
    */

    /* ------------------------------ RuleRegistry ------------------------------ */

    it("should not let unauthorized users create base rules", async function () {
      await expect(
        ruleRegistry.connect(attackerAsSigner).createRule("Bogus", "bogus", Operator.base, []),
      ).to.be.revertedWith("Unauthorized");
    });

    it("should not allow invalid rule records", async function () {
      const RULE_ID_PP_GB = await ruleRegistry.ruleAtIndex(2);
      const RULE_ID_PP_US = await ruleRegistry.ruleAtIndex(3);
      const RULE_ID_PEP = await ruleRegistry.ruleAtIndex(4);
      const bogusRuleId = ethers.utils.keccak256(await ruleRegistry.ruleAtIndex(0));

      const invalidExpressionRule = {
        description: "",
        uri: "",
        operator: Operator.union,
        operands: sortAscendingOrder([RULE_ID_PP_GB, RULE_ID_PP_US, RULE_ID_PEP]).reverse(),
      };

      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("operands must be declared in ascending ruleId order"));

      invalidExpressionRule.operator = Operator.complement;
      invalidExpressionRule.operands = [bogusRuleId];
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("operand not found"));

      invalidExpressionRule.description = "invalid expression rule";
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("only base rules can have a description"));

      invalidExpressionRule.description = "";
      invalidExpressionRule.uri = "https://example.com/invalid-expression-rule";
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("only base rules can have a uri"));

      invalidExpressionRule.operator = Operator.base;
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("base rules cannot have operands"));

      invalidExpressionRule.operands = [];
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("base rules must have a description"));

      invalidExpressionRule.description = "invalid expression rule";
      invalidExpressionRule.uri = "";
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("base rules must have a uri"));

      invalidExpressionRule.description = "";
      invalidExpressionRule.operator = Operator.complement;
      invalidExpressionRule.operands = sortAscendingOrder([RULE_ID_PP_GB, RULE_ID_PP_GB]);
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("complement must have exactly one operand"));

      invalidExpressionRule.operator = Operator.union;
      invalidExpressionRule.operands = [RULE_ID_PP_GB];
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("union must have two or more operands"));

      invalidExpressionRule.operator = Operator.intersection;
      await expect(
        ruleRegistry.createRule(
          invalidExpressionRule.description,
          invalidExpressionRule.uri,
          invalidExpressionRule.operator,
          invalidExpressionRule.operands,
        ),
      ).to.be.revertedWith(unacceptable("intersection must have two or more operands"));

      // create a valid expression rule
      const validExpressionRule = {
        description: "",
        uri: "",
        operator: Operator.union,
        operands: sortAscendingOrder([RULE_ID_PP_GB, RULE_ID_PP_US, RULE_ID_PEP]),
      };
      await ruleRegistry.createRule(
        validExpressionRule.description,
        validExpressionRule.uri,
        validExpressionRule.operator,
        validExpressionRule.operands,
      );

      await expect(
        ruleRegistry.createRule(
          validExpressionRule.description,
          validExpressionRule.uri,
          validExpressionRule.operator,
          validExpressionRule.operands,
        ),
      ).to.be.revertedWith(
        `SetConsistency("Bytes32Set", "insert", "exists", "RuleRegistry:createRule: generated duplicated id.")`,
      );

      const ruleCount = await ruleRegistry.ruleCount();
      const ruleId = await ruleRegistry.ruleAtIndex(ruleCount.toNumber() - 1);
      const rule = await ruleRegistry.rule(ruleId);
      const ruleDescription = await ruleRegistry.ruleDescription(ruleId);
      const ruleUri = await ruleRegistry.ruleUri(ruleId);
      const ruleOperator = await ruleRegistry.ruleOperator(ruleId);
      const ruleOperandCount = await ruleRegistry.ruleOperandCount(ruleId);

      expect(rule.description).to.equal(validExpressionRule.description);
      expect(ruleDescription).to.equal(validExpressionRule.description);
      expect(rule.uri).to.equal(validExpressionRule.uri);
      expect(ruleUri).to.equal(validExpressionRule.uri);
      expect(rule.operator).to.equal(validExpressionRule.operator);
      expect(ruleOperator).to.equal(validExpressionRule.operator);
      expect(rule.operandCount.toNumber()).to.deep.equal(validExpressionRule.operands.length);
      expect(ruleOperandCount.toNumber()).to.deep.equal(validExpressionRule.operands.length);

      await expect(ruleRegistry.ruleAtIndex(ruleCount.toNumber())).to.be.revertedWith("index out of range");

      for (let i = 0; i < rule.operandCount.toNumber(); i++) {
        const operand = await ruleRegistry.ruleOperandAtIndex(ruleId, i);
        expect(operand).to.equal(validExpressionRule.operands[i]);
      }

      await expect(ruleRegistry.ruleOperandAtIndex(ruleId, rule.operandCount.toNumber())).to.be.revertedWith(
        "index out of range",
      );

      // setToxic
      await ruleRegistry.setToxic(ruleId, true);
      expect(await ruleRegistry.ruleIsToxic(ruleId)).to.equal(true);
      await expect(ruleRegistry.setToxic(bogusRuleId, true)).to.be.revertedWith(unacceptable("ruleId not found"));
      await expect(ruleRegistry.connect(attackerAsSigner).setToxic(bogusRuleId, false)).to.be.revertedWith(
        "RuleRegistry:setToxic: only the RuleAdmin role can set isToxic",
      );

      // create another rule with the non-toxic rule
      validExpressionRule.operands = sortAscendingOrder([...validExpressionRule.operands, ruleId]);
      await ruleRegistry.createRule(
        validExpressionRule.description,
        validExpressionRule.uri,
        validExpressionRule.operator,
        validExpressionRule.operands,
      );

      // genesis rules
      const [universeRuleId, emptyRuleId] = await ruleRegistry.genesis();
      const universeRule = await ruleRegistry.ruleAtIndex(0);
      const emptyRule = await ruleRegistry.ruleAtIndex(1);
      expect(universeRuleId).to.equal(universeRule);
      expect(emptyRuleId).to.equal(emptyRule);

      expect(await ruleRegistry.ROLE_RULE_ADMIN()).to.equal(ROLE_RULE_ADMIN);
    });

    /* ------------------------------- WalletCheck ------------------------------ */
    it("should only let wallet check admin whitelist wallet addresses", async function () {
      expect((await walletCheck.birthday(bob)).toString()).to.equal("0");
      const now = await helpers.time.latest();
      await expect(walletCheck.connect(attackerAsSigner).setWalletWhitelist(bob, true, now)).to.be.revertedWith(
        unauthorized(
          attacker,
          "KeyringAccessControl",
          "_checkRole",
          ROLE_WALLETCHECK_ADMIN,
          "sender does not have the required role",
          "WalletCheck::onlyWalletCheckAdmin",
        ),
      );
      await walletCheck.setWalletWhitelist(bob, true, now);
      expect((await walletCheck.birthday(bob)).toNumber()).to.equal(now);
    });

    it("should not allow timestamps that are in the future", async function () {
      const now = await helpers.time.latest();
      await expect(walletCheck.setWalletWhitelist(bob, true, now + 100)).to.be.revertedWith(
        unacceptable("timestamp cannot be in the future"),
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

const unacceptable = (reason: string) => {
  return `Unacceptable("${reason}")`;
};

const unauthorized = (
  sender: string,
  module: string,
  method: string,
  role: string,
  reason: string,
  context: string,
) => {
  return `Unauthorized("${sender}", "${module}", "${method}", "${role}", "${reason}", "${context}")`;
};
