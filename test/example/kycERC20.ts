import { getNamedAccounts, ethers, waffle } from "hardhat";
import { createFixtureLoader } from "ethereum-waffle";
import { expect } from "chai";
import { toUtf8Bytes } from "ethers/lib/utils";

import {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  KeyringV1CredentialUpdater,
  KycERC20,
  MockERC20,
} from "../../src/types";
import { Operator, namedAccounts, baseRules, testPolicy, genesis } from "../../constants";
import { Attestation, SignedAttestation, signAttestation } from "../eip712/signUtil";
import { keyringTestFixture } from "../shared/fixtures";

const NULL_ADDRESS = ethers.constants.AddressZero;
const NULL_BYTES32 = ethers.constants.HashZero;
const tokenName = "Mock ERC20 token";
const tokenSymbol = "MERC20";
const tokenSupply = 10000;
const ONE_DAY_IN_SECONDS = 24 * 60 * 60;

/* -------------------------------------------------------------------------- */
/*        Test to ensure that the keyring guard is working accordingly.       */
/* -------------------------------------------------------------------------- */

describe("Compliant Token", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];
  const aliceWallet = wallets[namedAccounts["alice"]];
  const verifier1Wallet = wallets[namedAccounts["verifier1"]];

  let credentials: KeyringCredentials;
  let ruleRegistry: RuleRegistry;
  let policyManager: PolicyManager;
  let credentialsUpdater: KeyringV1CredentialUpdater;
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
    // `alice` connect's with contract
    this.aliceAsSigner = ethers.provider.getSigner(alice);
    // load pre-configuration (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  describe("kycERC20", function () {
    beforeEach(async function () {
      // load pre-configured contracts
      const fixture = await loadFixture(keyringTestFixture);
      credentials = fixture.credentials;
      ruleRegistry = fixture.ruleRegistry;
      policyManager = fixture.policyManager;
      credentialsUpdater = fixture.credentialsUpdater;

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
      const userPolicyId = await policyManager.policyAtIndex(0);
      const admissionPolicyId = await policyManager.policyAtIndex(0);
      // setup a quorum of 1 out of 2 required verifiers
      // add two verifiers to the policy
      await policyManager.addPolicyVerifiers(userPolicyId, [this.verifier1, this.verifier2]);
      // set requiredVerifiers to one
      await policyManager.updatePolicy(userPolicyId, testPolicy.description, RULE_ID_GBUS_EXCL_PEP, 1, ONE_DAY_IN_SECONDS);

      // admin needs a credential signed by a verifier

      // first, gather info for the message to sign
      const user = this.admin;
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      // the message is an instance of the Attestation type
      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        // false indicates this is a response from a VERIFIER signer that has responded in the affirmative.
        isRequest: false,
      };

      // chain and verifier are part of the EIP712 typedData to sign
      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      // signUtil returns a signedAttestion from the message, chain and receiverAddress, using the wallet with private key to generate the signature.
      // this object contains the information needed to successfully update the credentials.

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );

      const signatures = [signedAttestation.signature];

      // set Admin's policy to the first one
      await policyManager.setUserPolicy(userPolicyId);   
      
      // set Alice's policy to the first one
      await policyManager.connect(aliceWallet).setUserPolicy(userPolicyId);

      await credentialsUpdater.updateCredential(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        timestamp,
        signatures,
      );
    });

    it("should be ready to test", async function () {
      expect(true).to.equal(true);
    });

    it("should not permit deployment of an invalid configuration", async function () {
      const reasonPolicyManager = unacceptable(
        this.admin,
        "KeyringGuardImmutable",
        "constructor",
        "policyManager cannot be empty"
      );
      const reasonPolicyNull = unacceptable(
        this.admin,
        "KeyringGuardImmutable",
        "constructor",
        "admissionPolicyId cannot be empty"
      );
      const reasonPolicyNotFound = unacceptable(
        this.admin,
        "KeyringGuardImmutable",
        "constructor",
        "admissionPolicyId not found"
      );
      const reasonCredentials = unacceptable(
        this.admin,
        "KeyringGuardImmutable",
        "constructor",
        "credentials cannot be empty"
      );
      const reasonCollateral = unacceptable(
        this.admin,
        "KycERC20",
        "constructor",
        "collateral token cannot be empty"
      );
      const reasonName = unacceptable(
        this.admin,
        "KycERC20",
        "constructor",
        "name_ cannot be empty"
      );
      const reasonSymbol = unacceptable(
        this.admin,
        "KycERC20",
        "constructor",
        "symbol_ cannot be empty"
      );

      const mockERC20 = await deployMockERC20();
      const nullCollateral = (await ethers.getContractAt("MockERC20", NULL_ADDRESS)) as MockERC20;

      await expect(
        deployKycERC20(
          nullCollateral,
          credentials,
          policyManager,
          await policyManager.policyAtIndex(0),
          tokenName,
          tokenSymbol,
        ),
      ).to.be.revertedWith(reasonCollateral);

      const nullCredentials = (await ethers.getContractAt("KeyringCredentials", NULL_ADDRESS)) as KeyringCredentials;

      await expect(
        deployKycERC20(
          mockERC20,
          nullCredentials,
          policyManager,
          await policyManager.policyAtIndex(0),
          tokenName,
          tokenSymbol,
        ),
      ).to.be.revertedWith(reasonCredentials);

      const nullPolicyManager = (await ethers.getContractAt("PolicyManager", NULL_ADDRESS)) as PolicyManager;

      await expect(
        deployKycERC20(
          mockERC20,
          credentials,
          nullPolicyManager,
          await policyManager.policyAtIndex(0),
          tokenName,
          tokenSymbol,
        ),
      ).to.be.revertedWith(reasonPolicyManager);

      await expect(
        deployKycERC20(mockERC20, credentials, policyManager, NULL_BYTES32, tokenName, tokenSymbol),
      ).to.be.revertedWith(reasonPolicyNull);

      await expect(
        deployKycERC20(
          mockERC20,
          credentials,
          policyManager,
          ethers.utils.keccak256(toUtf8Bytes("missing")),
          tokenName,
          tokenSymbol,
        ),
      ).to.be.revertedWith(reasonPolicyNotFound);

      await expect(
        deployKycERC20(mockERC20, credentials, policyManager, await policyManager.policyAtIndex(0), "", tokenSymbol),
      ).to.be.revertedWith(reasonName);

      await expect(
        deployKycERC20(mockERC20, credentials, policyManager, await policyManager.policyAtIndex(0), tokenName, ""),
      ).to.be.revertedWith(reasonSymbol);
    });

    it("should be configured", async function () {
      const mockERC20 = await deployMockERC20();
      const kycERC20 = await deployKycERC20(
        mockERC20,
        credentials,
        policyManager,
        await policyManager.policyAtIndex(0),
        tokenName,
        tokenSymbol,
      );

      const credentialsAddress = await kycERC20.getKeyringCredentials();
      const policyManagerAddress = await kycERC20.getPolicyManager();
      const policyId = await kycERC20.getAdmissionPolicyId();
      const getTokenDecimals = await kycERC20.decimals();
      const getTokenName = await kycERC20.name();
      const getTokenSymbol = await kycERC20.symbol();
      const tokenGenesis = await kycERC20.genesis();
      const collateral = await kycERC20.collateral();

      expect(credentialsAddress).to.be.equal(credentials.address);
      expect(policyManagerAddress).to.be.equal(policyManager.address);
      expect(policyId).to.be.equal(await policyManager.policyAtIndex(0));
      expect(getTokenDecimals.toString()).to.equal("18");
      expect(getTokenName).to.equal(tokenName);
      expect(getTokenSymbol).to.equal(tokenSymbol);
      expect(tokenGenesis.universeRuleId).to.equal(await ruleRegistry.ruleAtIndex(0));
      expect(tokenGenesis.emptyRuleId).to.equal(await ruleRegistry.ruleAtIndex(1));
      expect(collateral).to.be.equal(mockERC20.address);
    });

    it("should meet the ERC20 transfer and transferFrom requirements", async function () {
      const errorAllowance = "ERC20: insufficient allowance";
      const errorBalanceTransfer = "ERC20: transfer amount exceeds balance";
      const errorBalanceBurn = "ERC20: burn amount exceeds balance";

      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();

      const admissionPolicyId = await policyManager.policyAtIndex(0);

      const kycERC20 = await deployKycERC20(mockERC20, credentials, policyManager, admissionPolicyId, tokenName, tokenSymbol);

      // alice needs a credential signed by a verifier
      const user = aliceWallet.address;
      const userPolicyId = await policyManager.policyAtIndex(0);
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        isRequest: false,
      };

      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );

      const signatures = [signedAttestation.signature];

      const tx0 = await credentialsUpdater.updateCredential(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        timestamp,
        signatures,
      );
      await tx0.wait();

      const kycERC20WithAlice = kycERC20.connect(this.aliceAsSigner);

      await expect(kycERC20WithAlice.depositFor(this.admin, 100)).to.be.revertedWith(errorAllowance);

      const tx1 = await mockERC20.connect(this.aliceAsSigner).approve(kycERC20.address, 100);
      await tx1.wait();
      expect(await mockERC20.allowance(this.alice, kycERC20.address)).to.be.equal("100");
      await expect(kycERC20WithAlice.depositFor(this.admin, 100)).to.be.revertedWith(errorBalanceTransfer);

      await expect(kycERC20WithAlice.withdrawTo(this.admin, 100)).to.be.revertedWith(errorBalanceBurn);
    });

    it("should depositFor and withdrawTo kycERC20", async function () {
      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();

      const admissionPolicyId = await policyManager.policyAtIndex(0);

      const kycERC20 = await deployKycERC20(mockERC20, credentials, policyManager, admissionPolicyId, tokenName, tokenSymbol);

      const tx1 = await mockERC20.approve(kycERC20.address, 100);
      await tx1.wait();

      const tx2 = await kycERC20.depositFor(this.admin, 100);
      await tx2.wait();

      let adminKycBalance = await kycERC20.balanceOf(this.admin);
      let contractMockBalance = await mockERC20.balanceOf(kycERC20.address);
      let senderMockBalance = await mockERC20.balanceOf(this.admin);
      expect(adminKycBalance.toString()).to.equal("100");
      expect(contractMockBalance).to.equal("100");
      expect(senderMockBalance.toString()).to.equal("9900");

      const tx3 = await kycERC20.approve(kycERC20.address, 50);
      await tx3.wait();

      const tx4 = await kycERC20.withdrawTo(this.admin, 50);
      await tx4.wait();

      adminKycBalance = await kycERC20.balanceOf(this.admin);
      contractMockBalance = await mockERC20.balanceOf(kycERC20.address);
      senderMockBalance = await mockERC20.balanceOf(this.admin);
      expect(adminKycBalance.toString()).to.equal("50");
      expect(contractMockBalance).to.equal("50");
      expect(senderMockBalance.toString()).to.equal("9950");
    });

    it("should not allow a transfer to a non-compliant wallet", async function () {
      const reason = "Compliance";

      const admissionPolicyId = await policyManager.policyAtIndex(0);

      const mockERC20 = await deployMockERC20();
      const kycERC20 = await deployKycERC20(mockERC20, credentials, policyManager, admissionPolicyId, tokenName, tokenSymbol);

      const tx1 = await mockERC20.approve(kycERC20.address, 100);
      await tx1.wait();

      const tx2 = await kycERC20.depositFor(this.admin, 100);
      await tx2.wait();

      await expect(kycERC20.transfer(aliceWallet.address, 50)).to.be.revertedWith(reason);
    });

    it("should allow a transfer to a compliant wallet", async function () {
      const mockERC20 = await deployMockERC20();

      const admissionPolicyId = await policyManager.policyAtIndex(0);
      const userPolicyId = await policyManager.policyAtIndex(0);

      const kycERC20 = await deployKycERC20(mockERC20, credentials, policyManager, admissionPolicyId, tokenName, tokenSymbol);

      const tx1 = await mockERC20.approve(kycERC20.address, 100);
      await tx1.wait();

      const tx2 = await kycERC20.depositFor(this.admin, 100);
      await tx2.wait();

      // alice needs a credential signed by a verifier
      const user = aliceWallet.address;
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        isRequest: false,
      };

      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );

      const signatures = [signedAttestation.signature];

      const tx3 = await credentialsUpdater.updateCredential(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        timestamp,
        signatures,
      );
      await tx3.wait();

      const tx4 = await kycERC20.transfer(aliceWallet.address, 40);
      await tx4.wait();

      let adminKycBalance = await kycERC20.balanceOf(this.admin);
      let aliceKycBalance = await kycERC20.balanceOf(this.alice);
      expect(adminKycBalance.toString()).to.equal("60");
      expect(aliceKycBalance).to.equal("40");

      const tx5 = await kycERC20.approve(aliceWallet.address, 25);
      await tx5.wait();

      const tx6 = await kycERC20.connect(this.aliceAsSigner).transferFrom(this.admin, aliceWallet.address, 25);
      await tx6.wait();

      adminKycBalance = await kycERC20.balanceOf(this.admin);
      aliceKycBalance = await kycERC20.balanceOf(aliceWallet.address);
      expect(adminKycBalance.toString()).to.equal("35");
      expect(aliceKycBalance).to.equal("65");
    });

    it("should allow trading when both parties use the universeRule", async function () {
      const universeRule = await ruleRegistry.ruleAtIndex(0);

      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();

      await policyManager.createPolicy("universeRulePolicy", universeRule, ONE_DAY_IN_SECONDS);
      const index = Number(await policyManager.policyCount()) - 1;
      const universeRulePolicy = await policyManager.policyAtIndex(index);

      const kycERC20 = await deployKycERC20(
        mockERC20,
        credentials,
        policyManager,
        universeRulePolicy,
        tokenName,
        tokenSymbol,
      );
      await kycERC20.genesis();

      await policyManager.setUserPolicy(universeRulePolicy);
      await policyManager.connect(this.aliceAsSigner).setUserPolicy(universeRulePolicy);

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(this.admin, 100);
      await kycERC20.transfer(aliceWallet.address, 100);
    });

    it("should not allow trading when one of both parties use the emptyRule", async function () {
      const emptyRule = await ruleRegistry.ruleAtIndex(1);

      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();

      await policyManager.createPolicy("emptyRulePolicy", emptyRule, ONE_DAY_IN_SECONDS);
      const index = Number(await policyManager.policyCount()) - 1;
      const emptyRulePolicy = await policyManager.policyAtIndex(index);

      const kycERC20 = await deployKycERC20(
        mockERC20,
        credentials,
        policyManager,
        emptyRulePolicy,
        tokenName,
        tokenSymbol,
      );
      await kycERC20.genesis();

      await policyManager.setUserPolicy(emptyRulePolicy);

      await mockERC20.approve(kycERC20.address, 100);
      await expect(kycERC20.depositFor(this.admin, 100)).to.be.revertedWith("stale credential or no credential");
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

const deployKycERC20 = async function (
  collateral: MockERC20,
  credentials: KeyringCredentials,
  policyManager: PolicyManager,
  userPolicyId: string,
  name: string,
  symbol: string,
) {
  const kycERC20Factory = await ethers.getContractFactory("KycERC20");

  const kycERC20 = (await kycERC20Factory.deploy(
    collateral.address,
    credentials.address,
    policyManager.address,
    userPolicyId,
    name,
    symbol,
  )) as KycERC20;
  await kycERC20.deployed();
  return kycERC20;
};

const deployMockERC20 = async function () {
  const MockERC20Factory = await ethers.getContractFactory("MockERC20");
  const mockERC20 = (await MockERC20Factory.deploy(tokenName, tokenSymbol, tokenSupply)) as MockERC20;
  await mockERC20.deployed();
  return mockERC20;
};

function sortAscendingOrder(ruleIds: string[]) {
  return ruleIds.sort();
}

// function generates custom error message
const unacceptable = (sender: string, module: string, method: string, reason: string) => {
  return `Unacceptable("${sender}", "${module}", "${method}", "${reason}")`;
};

