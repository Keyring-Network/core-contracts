import { Signer, Wallet } from "ethers";
import { getNamedAccounts, ethers, waffle, upgrades } from "hardhat";
import { createFixtureLoader } from "ethereum-waffle";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { keyringTestFixture } from "../shared/fixtures";
import type {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  KeyringZkCredentialUpdater,
  WalletCheck,
  IdentityTree,
  MockERC20,
  KycERC20,
  UserPolicies,
  NoImplementation,
} from "../../src/types";
import { PolicyStorage } from "../../src/types/PolicyManager";
import {
  namedAccounts,
  membershipProof2,
  authorisationProof2,
  proofMerkleRoot2,
  trader2,
  trader3,
  proofMerkleRoot3,
  authorisationProof3,
  membershipProof3,
  NULL_ADDRESS,
  NULL_BYTES32,
  THIRTY_DAYS_IN_SECONDS,
} from "../../constants";

const TOKEN_NAME = "Mock ERC20 token";
const TOKEN_SYMBOL = "MERC20";
const TOKEN_SUPPLY = 10000;

/* -------------------------------------------------------------------------- */
/*        Test to ensure that the keyring guard is working accordingly.       */
/* -------------------------------------------------------------------------- */

describe("Compliant Token", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];
  const aliceWallet = wallets[namedAccounts["alice"]];

  // prepare contracts with interfaces
  let forwarder: NoImplementation;
  let credentials: KeyringCredentials;
  let ruleRegistry: RuleRegistry;
  let userPolicies: UserPolicies;
  let policyManager: PolicyManager;
  let credentialsUpdater: KeyringZkCredentialUpdater;
  let walletCheck: WalletCheck;
  let identityTree: IdentityTree;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  // policy struct to be used in tests
  let policyScalar: PolicyStorage.PolicyScalarStruct;

  // accounts in this test
  let admin: string;
  let bob: string;
  let bobAsSigner: Signer;
  let traderAsSigner2: Signer;
  let traderAsSigner3: Signer;
  let attacker: string;
  let attackerAsSigner: Signer;

  before(async () => {
    const { admin: adminAddress, bob: bobAddress, attacker: attackerAddress } = await getNamedAccounts();
    admin = adminAddress;
    bob = bobAddress;
    bobAsSigner = ethers.provider.getSigner(bob);
    // set up trader wallets with 2000 ETH each
    traderAsSigner2 = new Wallet(trader2.priv, provider);
    traderAsSigner3 = new Wallet(trader3.priv, provider);
    await adminWallet.sendTransaction({ to: trader2.address, value: ethers.utils.parseEther("2000") });
    await adminWallet.sendTransaction({ to: trader3.address, value: ethers.utils.parseEther("2000") });
    // `attacker` connect's with contract and try to sign invalid
    attacker = attackerAddress;
    attackerAsSigner = ethers.provider.getSigner(attacker);

    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  describe("kycERC20", function () {
    beforeEach(async function () {
      // load pre-configured contracts
      const fixture = await loadFixture(keyringTestFixture);
      forwarder = fixture.contracts.forwarder;
      credentials = fixture.contracts.credentials;
      ruleRegistry = fixture.contracts.ruleRegistry;
      userPolicies = fixture.contracts.userPolicies;
      policyManager = fixture.contracts.policyManager;
      credentialsUpdater = fixture.contracts.credentialsUpdater;
      walletCheck = fixture.contracts.walletCheck;
      identityTree = fixture.contracts.identityTree;

      policyScalar = fixture.policyScalar;

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      // update credentials for two traders
      // first set merkle root birthday
      const now = await helpers.time.latest();

      await identityTree.setMerkleRootBirthday(proofMerkleRoot2, now);
      await identityTree.setMerkleRootBirthday(proofMerkleRoot3, now);

      // update credentials
      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);
      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof3, authorisationProof3);

      // whitelist trader
      const whitelistTime = await helpers.time.latest();
      await walletCheck.setWalletWhitelist(trader2.address, true, whitelistTime);
      expect((await walletCheck.birthday(trader2.address)).toString()).to.equal(whitelistTime.toString());
      await walletCheck.setWalletWhitelist(trader3.address, true, whitelistTime);
      expect((await walletCheck.birthday(trader3.address)).toString()).to.equal(whitelistTime.toString());

      // check if credentials are set properly
      const version = 1;
      let unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[0]);
      let unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[1]);
      let policies = [...unpacked1, ...unpacked2];
      for (let i = 0; i < policies.length; i++) {
        const timestamp = await credentials.getCredential(version, trader2.address, policies[i]);
        policies[i] === 0 ? expect(timestamp.toNumber()).to.be.equal(0) : expect(timestamp.toNumber()).to.be.equal(now);
      }
      unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof3.policyDisclosures[0]);
      unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof3.policyDisclosures[1]);
      policies = [...unpacked1, ...unpacked2];
      for (let i = 0; i < policies.length; i++) {
        const timestamp = await credentials.getCredential(version, trader3.address, policies[i]);
        policies[i] === 0 ? expect(timestamp.toNumber()).to.be.equal(0) : expect(timestamp.toNumber()).to.be.equal(now);
      }
    });

    it("should allow users to set a whitelisting option when allowed by the policy", async function () {
      // add trader/bob to whitelist of admin
      expect(await userPolicies.isWhitelisted(admin, bob)).to.be.false;
      await userPolicies.addWhitelistedTrader(bob);
      expect(await userPolicies.isWhitelisted(admin, bob)).to.be.true;
      const traderWhitelistedCount = await userPolicies.whitelistedTraderCount(admin);
      expect(traderWhitelistedCount.toString()).to.be.equal("1");
      expect(await userPolicies.whitelistedTraderAtIndex(admin, traderWhitelistedCount.sub(1))).to.be.equal(bob);

      // if policy is not allowing whitelisting, it should ignore the whitelist
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );
      await mockERC20.approve(kycERC20.address, 100);
      await expect(kycERC20.depositFor(admin, 100)).to.be.revertedWith(unacceptable("trader not authorized"));

      // if policy is allowing whitelisting, it should allow the transfer
      // BUT only when parties are whitelisted

      // first set policy to allow whitelisting
      const now = await helpers.time.latest();
      const timeToNextBlock = 1; // 1 second, because the next block is happening 1 second after now
      const deadline = now + THIRTY_DAYS_IN_SECONDS + timeToNextBlock;
      await policyManager.updatePolicyAllowWhitelists(admissionPolicyId, true, deadline);
      await helpers.time.increaseTo(deadline);
      await policyManager.policy(admissionPolicyId);
      expect(await policyManager.callStatic.policyAllowWhitelists(admissionPolicyId)).to.be.true;

      await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));

      // NOTE trader needs to whitelist themself for depositFor
      await expect(kycERC20.depositFor(admin, 100)).to.be.revertedWith(unacceptable("trader not authorized"));
      await userPolicies.addWhitelistedTrader(admin);
      await kycERC20.depositFor(admin, 100);

      await userPolicies.connect(bobAsSigner).addWhitelistedTrader(admin);
      await kycERC20.transfer(bob, 40);

      const adminKycBalance = await kycERC20.balanceOf(admin);
      const bobKycBalance = await kycERC20.balanceOf(bob);
      expect(adminKycBalance.toString()).to.equal("60");
      expect(bobKycBalance.toString()).to.equal("40");

      // missing whitelisting in WalletCheck should not affect the transfer
      expect((await walletCheck.birthday(admin)).toString()).to.equal("0");
      expect((await walletCheck.birthday(bob)).toString()).to.equal("0");

      // remove trader from whitelist
      await userPolicies.removeWhitelistedTrader(bob);
      expect(await userPolicies.isWhitelisted(admin, bob)).to.be.false;
      await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));
    });

    it("should not permit deployment of an invalid configuration", async function () {
      const mockERC20 = await deployMockERC20();

      const nullCredentials = (await ethers.getContractAt("KeyringCredentials", NULL_ADDRESS)) as KeyringCredentials;
      await expect(
        deployKycERC20(forwarder, mockERC20, nullCredentials, userPolicies, policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("credentials cannot be empty"));

      const nullUserPolicies = (await ethers.getContractAt("UserPolicies", NULL_ADDRESS)) as UserPolicies;
      await expect(
        deployKycERC20(forwarder, mockERC20, credentials, nullUserPolicies, policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("userPolicies cannot be empty"));

      const nullPolicyManager = (await ethers.getContractAt("PolicyManager", NULL_ADDRESS)) as PolicyManager;
      await expect(
        deployKycERC20(forwarder, mockERC20, credentials, userPolicies, nullPolicyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("policyManager cannot be empty"));

      await expect(
        deployKycERC20(forwarder, mockERC20, credentials, userPolicies, policyManager, 99, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("admissionPolicyId not found"));

      const nullCollateral = (await ethers.getContractAt("MockERC20", NULL_ADDRESS)) as MockERC20;
      await expect(
        deployKycERC20(
          forwarder,
          nullCollateral,
          credentials,
          userPolicies,
          policyManager,
          0,
          TOKEN_NAME,
          TOKEN_SYMBOL,
        ),
      ).to.be.revertedWith(unacceptable("collateral token cannot be empty"));

      await expect(
        deployKycERC20(forwarder, mockERC20, credentials, userPolicies, policyManager, 0, "", TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("name_ cannot be empty"));

      await expect(
        deployKycERC20(forwarder, mockERC20, credentials, userPolicies, policyManager, 0, TOKEN_NAME, ""),
      ).to.be.revertedWith(unacceptable("symbol_ cannot be empty"));

      // empty genesis rules
      const universeRule = "0x0000000000000000000000000000000000000000000000000000000000000001";
      const emptyRule = "0x0000000000000000000000000000000000000000000000000000000000000002";

      const { _policyManager, _mockERC20 } = await mockInvalidRuleRegistry(NULL_BYTES32, emptyRule);

      await expect(
        deployKycERC20(forwarder, _mockERC20, credentials, userPolicies, _policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("the universe rule is not defined in the PolicyManager's RuleRegistry"));

      const { _policyManager: __policyManager, _mockERC20: __mockERC20 } = await mockInvalidRuleRegistry(
        universeRule,
        NULL_BYTES32,
      );

      await expect(
        deployKycERC20(forwarder, __mockERC20, credentials, userPolicies, __policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("the empty rule is not defined in the PolicyManager's RuleRegistry"));
    });

    it("should be configured", async function () {
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      const credentialsAddress = await kycERC20.keyringCredentials();
      const policyManagerAddress = await kycERC20.policyManager();
      const policyId = await kycERC20.admissionPolicyId();
      const getTokenDecimals = await kycERC20.decimals();
      const getTokenName = await kycERC20.name();
      const getTokenSymbol = await kycERC20.symbol();
      const universeRuleId = await kycERC20.universeRule();
      const emptyRuleId = await kycERC20.emptyRule();

      expect(credentialsAddress).to.be.equal(credentials.address);
      expect(policyManagerAddress).to.be.equal(policyManager.address);
      expect(policyId).to.be.equal(admissionPolicyId);
      expect(getTokenDecimals.toString()).to.equal("18");
      expect(getTokenName).to.equal(TOKEN_NAME);
      expect(getTokenSymbol).to.equal(TOKEN_SYMBOL);
      expect(universeRuleId).to.equal(await ruleRegistry.ruleAtIndex(0));
      expect(emptyRuleId).to.equal(await ruleRegistry.ruleAtIndex(1));
    });

    it("should meet the ERC20 transfer and transferFrom requirements", async function () {
      const errorAllowance = "ERC20: insufficient allowance";
      const errorBalanceTransfer = "ERC20: transfer amount exceeds balance";
      const errorBalanceBurn = "ERC20: burn amount exceeds balance";

      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();
      const admissionPolicyId = 1;
      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      // check isCompliant
      expect(await kycERC20.callStatic.checkCache(trader2.address)).to.be.equal(true);

      const kycERC20WithTrader = kycERC20.connect(traderAsSigner2);

      await expect(kycERC20WithTrader.depositFor(trader2.address, 100)).to.be.revertedWith(errorAllowance);
      await expect(kycERC20WithTrader.transferFrom(trader2.address, trader2.address, 100)).to.be.revertedWith(
        errorAllowance,
      );

      await mockERC20.connect(traderAsSigner2).approve(kycERC20.address, 100);
      expect(await mockERC20.allowance(trader2.address, kycERC20.address)).to.be.equal("100");
      await expect(kycERC20WithTrader.depositFor(trader2.address, 100)).to.be.revertedWith(errorBalanceTransfer);

      await expect(kycERC20WithTrader.withdrawTo(trader2.address, 100)).to.be.revertedWith(errorBalanceBurn);
    });

    it("should depositFor and withdrawTo kycERC20", async function () {
      const mockERC20 = await deployMockERC20(traderAsSigner2);
      await mockERC20.deployed();

      const admissionPolicyId = 1;

      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(trader2.address, 100);

      let kycBalance = await kycERC20.balanceOf(trader2.address);
      let contractMockBalance = await mockERC20.balanceOf(kycERC20.address);
      let senderMockBalance = await mockERC20.balanceOf(trader2.address);
      expect(kycBalance.toString()).to.equal("100");
      expect(contractMockBalance).to.equal("100");
      expect(senderMockBalance.toString()).to.equal("9900");

      await kycERC20.approve(kycERC20.address, 50);
      await kycERC20.withdrawTo(trader2.address, 50);

      kycBalance = await kycERC20.balanceOf(trader2.address);
      contractMockBalance = await mockERC20.balanceOf(kycERC20.address);
      senderMockBalance = await mockERC20.balanceOf(trader2.address);
      expect(kycBalance.toString()).to.equal("50");
      expect(contractMockBalance).to.equal("50");
      expect(senderMockBalance.toString()).to.equal("9950");
    });

    it("should not allow a transfer to a non-compliant wallet", async function () {
      const admissionPolicyId = 1;

      const mockERC20 = await deployMockERC20(traderAsSigner2);
      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(trader2.address, 100);

      await expect(kycERC20.transfer(aliceWallet.address, 50)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );
    });

    it("should allow a transfer to a compliant wallet", async function () {
      const mockERC20 = await deployMockERC20(traderAsSigner2);

      const admissionPolicyId = 1;

      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(trader2.address, 100);
      await kycERC20.transfer(trader3.address, 40);

      let kycBalanceTrader2 = await kycERC20.balanceOf(trader2.address);
      let kycBalanceTrader3 = await kycERC20.balanceOf(trader3.address);
      expect(kycBalanceTrader2).to.equal("60");
      expect(kycBalanceTrader3).to.equal("40");

      await kycERC20.connect(traderAsSigner3).approve(trader3.address, 25);
      await kycERC20.connect(traderAsSigner3).transferFrom(trader3.address, trader2.address, 25);

      kycBalanceTrader2 = await kycERC20.balanceOf(trader2.address);
      kycBalanceTrader3 = await kycERC20.balanceOf(trader3.address);
      expect(kycBalanceTrader2).to.equal("85");
      expect(kycBalanceTrader3).to.equal("15");
    });

    it("should allow trading when both parties use the universeRule", async function () {
      const universeRule = await ruleRegistry.ruleAtIndex(0);

      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();

      const universeRulePolicyScalar = {
        ...policyScalar,
        ruleId: universeRule,
      };

      await policyManager.createPolicy(universeRulePolicyScalar, [identityTree.address], [walletCheck.address]);
      const universeRulePolicy = Number(await policyManager.policyCount()) - 1;

      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        universeRulePolicy,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      // whitelisting in WalletCheck is still required for the universeRule
      await expect(kycERC20.depositFor(admin, 100)).to.be.revertedWith(unacceptable("trader not authorized"));
      await expect(kycERC20.transfer(aliceWallet.address, 40)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );

      const now = await helpers.time.latest();
      await walletCheck.setWalletWhitelist(admin, true, now);
      await walletCheck.setWalletWhitelist(aliceWallet.address, true, now);

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(admin, 100);
      await kycERC20.transfer(aliceWallet.address, 40);

      const adminKycBalance = await kycERC20.balanceOf(admin);
      const aliceKycBalance = await kycERC20.balanceOf(aliceWallet.address);
      expect(adminKycBalance.toString()).to.equal("60");
      expect(aliceKycBalance).to.equal("40");
    });

    it("should not allow trading when one of both parties use the emptyRule", async function () {
      const emptyRule = await ruleRegistry.ruleAtIndex(1);

      const mockERC20 = await deployMockERC20(traderAsSigner2);
      await mockERC20.deployed();

      const emptyRulePolicyScalar = {
        ...policyScalar,
        ruleId: emptyRule,
      };

      await policyManager.createPolicy(emptyRulePolicyScalar, [identityTree.address], [walletCheck.address]);
      const emptyRulePolicy = Number(await policyManager.policyCount()) - 1;

      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        emptyRulePolicy,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await userPolicies.connect(traderAsSigner2).setUserPolicy(emptyRulePolicy);

      await mockERC20.approve(kycERC20.address, 100);
      await expect(kycERC20.depositFor(trader2.address, 100)).to.be.revertedWith(unacceptable("trader not authorized"));
    });

    it("should reject Policy B by wallet check whitelist check after Policy A credential is refreshed", async function () {
      // check that user has valid credential for Policy B and wallet is whitelisted in WalletCheck
      const policyA = 3;
      const policyB = 4;

      const mockERC20 = await deployMockERC20(traderAsSigner2);

      const admissionPolicyId = policyB;

      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await mockERC20.approve(kycERC20.address, 1000);
      await kycERC20.depositFor(trader2.address, 100);

      let kycBalanceTrader2 = await kycERC20.balanceOf(trader2.address);
      expect(kycBalanceTrader2).to.equal("100");

      // user updates credential for Policy A
      // NOTE proof incluceds Policy B as well as Policy A
      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);

      await kycERC20.depositFor(trader2.address, 100);
      kycBalanceTrader2 = await kycERC20.balanceOf(trader2.address);
      expect(kycBalanceTrader2).to.equal("200");
    });

    it("should allow policy admin to maintain a global list of whitelisted addresses", async function () {
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      const kycERC20 = await deployKycERC20(
        forwarder,
        mockERC20,
        credentials,
        userPolicies,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      expect((await kycERC20.whitelistAddressCount()).toNumber()).to.be.equal(0);
      expect(await kycERC20.isWhitelisted(bob)).to.be.equal(false);

      await expect(kycERC20.connect(attackerAsSigner).whitelistAddress(bob)).to.be.revertedWith(
        "sender does not have the required role",
      );
      await kycERC20.whitelistAddress(bob);
      expect((await kycERC20.whitelistAddressCount()).toNumber()).to.be.equal(1);
      expect(await kycERC20.isWhitelisted(bob)).to.be.equal(true);
      expect(await kycERC20.whitelistAddressAtIndex(0)).to.be.equal(bob);
      await expect(kycERC20.whitelistAddress(bob)).to.be.revertedWith(unacceptable("subject is already whitelisted"));

      // allow whitelisting
      const now = await helpers.time.latest();
      const timeToNextBlock = 1; // 1 second, because the next block is happening 1 second after now
      const deadline = now + THIRTY_DAYS_IN_SECONDS + timeToNextBlock;
      await policyManager.updatePolicyAllowWhitelists(admissionPolicyId, true, deadline);
      await helpers.time.increaseTo(deadline);
      await policyManager.policy(admissionPolicyId);
      expect(await policyManager.callStatic.policyAllowWhitelists(admissionPolicyId)).to.be.true;

      // trader needs to whitelist themself for depositFor
      await userPolicies.addWhitelistedTrader(admin);
      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(admin, 100);
      
      // from must whitelist to
      await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));
      await userPolicies.connect(bobAsSigner).addWhitelistedTrader(admin);
      await kycERC20.transfer(bob, 40)

      const adminKycBalance = await kycERC20.balanceOf(admin);
      const bobKycBalance = await kycERC20.balanceOf(bob);
      expect(adminKycBalance.toString()).to.equal("60");
      expect(bobKycBalance.toString()).to.equal("40");
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

const deployKycERC20 = async function (
  forwarder: NoImplementation,
  collateral: MockERC20,
  credentials: KeyringCredentials,
  userPolicies: UserPolicies,
  policyManager: PolicyManager,
  policyId: number,
  name: string,
  symbol: string,
  deployer?: Signer,
) {
  const kycERC20Factory = await ethers.getContractFactory("KycERC20");

  const kycERC20 = (
    deployer
      ? await kycERC20Factory
          .connect(deployer)
          .deploy(
            forwarder.address,
            collateral.address,
            credentials.address,
            policyManager.address,
            userPolicies.address,
            policyId,
            name,
            symbol,
          )
      : await kycERC20Factory.deploy(
          forwarder.address,
          collateral.address,
          credentials.address,
          policyManager.address,
          userPolicies.address,
          policyId,
          name,
          symbol,
        )
  ) as KycERC20;
  await kycERC20.deployed();
  return kycERC20;
};

const deployMockERC20 = async function (deployer?: Signer) {
  const MockERC20Factory = await ethers.getContractFactory("MockERC20");

  const mockERC20 = (
    deployer
      ? await MockERC20Factory.connect(deployer).deploy(TOKEN_NAME, TOKEN_SYMBOL, TOKEN_SUPPLY)
      : await MockERC20Factory.deploy(TOKEN_NAME, TOKEN_SYMBOL, TOKEN_SUPPLY)
  ) as MockERC20;
  await mockERC20.deployed();
  return mockERC20;
};

// function generates custom error message
const unacceptable = (reason: string) => {
  return `Unacceptable("${reason}")`;
};

const mockInvalidRuleRegistry = async function (universeRule: string, emptyRule: string) {
  const randomAddress = "0x44017a895f26275166b1d449BCb1573fD324b456";
  const MockRuleRegistryFactory = await ethers.getContractFactory("MockRuleRegistry");
  const MockRuleRegistry = (await MockRuleRegistryFactory.deploy(
    randomAddress,
    universeRule,
    emptyRule,
  )) as RuleRegistry;
  await MockRuleRegistry.deployed();

  const PolicyStorageFactory = await ethers.getContractFactory("PolicyStorage");
  const PolicyStorage = await PolicyStorageFactory.deploy();
  await PolicyStorage.deployed();
  const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager", {
    libraries: {
      PolicyStorage: PolicyStorage.address,
    },
  });
  const _policyManager = (await upgrades.deployProxy(PolicyManagerFactory, {
    constructorArgs: [randomAddress, MockRuleRegistry.address],
    unsafeAllow: ["constructor", "delegatecall", "state-variable-immutable", "external-library-linking"],
  })) as PolicyManager;
  await _policyManager.deployed();
  await _policyManager.init();

  const _mockERC20 = await deployMockERC20();

  return { _policyManager, _mockERC20 };
};
