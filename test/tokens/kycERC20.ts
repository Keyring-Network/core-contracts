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
  ExemptionsManager,
  KycERC20__factory,
  IdentityTree__factory,
  WalletCheck__factory,
} from "../../src/types";
import { PolicyStorage } from "../../src/types/PolicyManager";
import {
  namedAccounts,
  NULL_ADDRESS,
  NULL_BYTES32,
  THIRTY_DAYS_IN_SECONDS,
  MAXIMUM_CONSENT_PERIOD,
  trader0,
  membershipProof0,
  authorisationProof0,
  authorisationProof1,
  trader1,
  membershipProof1,
  defaultDegradationPeriod,
  defaultFreshnessPeriod,
  policyDisablementPeriod,
  ONE_DAY_IN_SECONDS,
} from "../constants";
import { IKeyringGuard } from "../../src/types/KycERC20";

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
  let exemptionsManager: ExemptionsManager;

  // KeyringConfig for kycERC20
  let config: IKeyringGuard.KeyringConfigStruct;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  // policy struct to be used in tests
  let policyScalar: PolicyStorage.PolicyScalarStruct;

  // accounts in this test
  let admin: string;
  let bob: string;
  let bobAsSigner: Signer;
  let traderAsSigner0: Signer;
  let traderAsSigner1: Signer;
  let attacker: string;
  let attackerAsSigner: Signer;
  let attestor1: string;
  let attestor2: string;

  before(async () => {
    const {
      admin: adminAddress,
      bob: bobAddress,
      attacker: attackerAddress,
      attestor1: attestor1Address,
      attestor2: attestor2Address,
    } = await getNamedAccounts();
    admin = adminAddress;
    bob = bobAddress;
    bobAsSigner = ethers.provider.getSigner(bob);
    attestor1 = attestor1Address;
    attestor2 = attestor2Address;
    // set up trader wallets with 2000 ETH each
    traderAsSigner0 = new Wallet(trader0.priv, provider);
    traderAsSigner1 = new Wallet(trader1.priv, provider);
    await adminWallet.sendTransaction({ to: trader0.address, value: ethers.utils.parseEther("2000") });
    await adminWallet.sendTransaction({ to: trader1.address, value: ethers.utils.parseEther("2000") });
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
      exemptionsManager = fixture.contracts.exemptionsManager;

      config = {
        trustedForwarder: forwarder.address,
        keyringCredentials: credentials.address,
        policyManager: policyManager.address,
        userPolicies: userPolicies.address,
        exemptionsManager: exemptionsManager.address,
        collateralToken: NULL_ADDRESS,
      };

      policyScalar = fixture.policyScalar;

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      // update credentials for two traders
      // first set merkle root birthday
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(membershipProof0.root as string, now);

      // update credentials
      await credentialsUpdater
        .connect(traderAsSigner0)
        .updateCredentials(identityTree.address, membershipProof0, authorisationProof0);
      await credentialsUpdater
        .connect(traderAsSigner1)
        .updateCredentials(identityTree.address, membershipProof1, authorisationProof1);
      // whitelist trader
      const whitelistTime = await helpers.time.latest();
      await walletCheck.setWalletCheck(trader0.address, true, whitelistTime);
      await walletCheck.setWalletCheck(trader1.address, true, whitelistTime);
      expect((await walletCheck.subjectUpdates(walletCheckKeyGen(trader1.address))).toString()).to.equal(
        whitelistTime.toString(),
      );
      expect((await walletCheck.subjectUpdates(walletCheckKeyGen(trader1.address))).toString()).to.equal(
        whitelistTime.toString(),
      );

      // check if credentials are set properly
      let unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof0.policyDisclosures[0]);
      let unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof0.policyDisclosures[1]);
      let policies = [...unpacked1, ...unpacked2];
      for (let i = 0; i < policies.length; i++) {
        const key = await credentials.keyGen(trader0.address, policies[i]);
        const timestamp = await credentials.subjectUpdates(key);
        policies[i] === 0 ? expect(timestamp.toNumber()).to.be.equal(0) : expect(timestamp.toNumber()).to.be.equal(now);
      }
      unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof1.policyDisclosures[0]);
      unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof1.policyDisclosures[1]);
      policies = [...unpacked1, ...unpacked2];
      for (let i = 0; i < policies.length; i++) {
        const key = await credentials.keyGen(trader1.address, policies[i]);
        const timestamp = await credentials.subjectUpdates(key);
        policies[i] === 0 ? expect(timestamp.toNumber()).to.be.equal(0) : expect(timestamp.toNumber()).to.be.equal(now);
      }
    });

    it("should allow users to set a whitelisting option when allowed by the policy", async function () {
      // add trader/bob to whitelist of admin
      expect(await userPolicies.isApproved(admin, bob)).to.be.false;
      await userPolicies.addApprovedCounterparties([bob, aliceWallet.address]);
      expect(await userPolicies.isApproved(admin, bob)).to.be.true;
      const traderWhitelistedCount = await userPolicies.approvedCounterpartyCount(admin);
      expect(traderWhitelistedCount.toString()).to.be.equal("2");
      expect(await userPolicies.approvedCounterpartyAtIndex(admin, traderWhitelistedCount.sub(2))).to.be.equal(bob);
      expect(await userPolicies.approvedCounterpartyAtIndex(admin, traderWhitelistedCount.sub(1))).to.be.equal(
        aliceWallet.address,
      );

      // if policy is not allowing whitelisting, it should ignore the whitelist
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };
      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );
      await mockERC20.approve(kycERC20.address, 100);

      // if policy is allowing whitelisting, it should allow the transfer
      // BUT only when parties are whitelisted

      // first set policy to allow whitelisting
      const now = await helpers.time.latest();
      const timeToNextBlock = 1; // 1 second, because the next block is happening 1 second after now
      const deadline = now + THIRTY_DAYS_IN_SECONDS + timeToNextBlock;
      await policyManager.updatePolicyAllowApprovedCounterparties(admissionPolicyId, true, deadline);
      await helpers.time.increaseTo(deadline);
      await policyManager.policy(admissionPolicyId);
      const policyObj = await policyManager.callStatic.policy(admissionPolicyId);
      expect(policyObj.config.allowApprovedCounterparties).to.be.true;

      await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));

      await kycERC20.depositFor(admin, 100);
      await userPolicies.connect(bobAsSigner).addApprovedCounterparty(admin);
      await kycERC20.transfer(bob, 40);

      const adminKycBalance = await kycERC20.balanceOf(admin);
      const bobKycBalance = await kycERC20.balanceOf(bob);
      expect(adminKycBalance.toString()).to.equal("60");
      expect(bobKycBalance.toString()).to.equal("40");

      // missing whitelisting in WalletCheck should not affect the transfer
      expect((await walletCheck.subjectUpdates(walletCheckKeyGen(admin))).toString()).to.equal("0");
      expect((await walletCheck.subjectUpdates(walletCheckKeyGen(bob))).toString()).to.equal("0");

      // remove trader from whitelist
      await userPolicies.removeApprovedCounterparties([bob, aliceWallet.address]);
      expect(await userPolicies.isApproved(admin, bob)).to.be.false;
      expect(await userPolicies.isApproved(admin, aliceWallet.address)).to.be.false;
      await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));
    });

    it("should not permit deployment of an invalid configuration", async function () {
      const mockERC20 = await deployMockERC20();

      const nullCredentials = (await ethers.getContractAt("KeyringCredentials", NULL_ADDRESS)) as KeyringCredentials;
      config = {
        ...config,
        collateralToken: mockERC20.address,
        keyringCredentials: nullCredentials.address,
      };
      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("credentials_ cannot be empty"),
      );

      const nullUserPolicies = (await ethers.getContractAt("UserPolicies", NULL_ADDRESS)) as UserPolicies;
      config = {
        ...config,
        keyringCredentials: credentials.address,
        userPolicies: nullUserPolicies.address,
      };
      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("userPolicies_ cannot be empty"),
      );

      const nullPolicyManager = (await ethers.getContractAt("PolicyManager", NULL_ADDRESS)) as PolicyManager;
      config = {
        ...config,
        userPolicies: userPolicies.address,
        policyManager: nullPolicyManager.address,
      };
      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("policyManager_ cannot be empty"),
      );

      config = {
        ...config,
        policyManager: policyManager.address,
      };
      await expect(deployKycERC20(config, 99, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("admissionPolicyId not found"),
      );

      const nullCollateral = (await ethers.getContractAt("MockERC20", NULL_ADDRESS)) as MockERC20;
      config = {
        ...config,
        collateralToken: nullCollateral.address,
      };
      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("collateral token cannot be empty"),
      );

      config = {
        ...config,
        collateralToken: mockERC20.address,
        exemptionsManager: NULL_ADDRESS,
      };
      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("exemptionsManager_ cannot be empty"),
      );

      config = {
        ...config,
        exemptionsManager: exemptionsManager.address,
        collateralToken: mockERC20.address,
      };
      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, "", TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("name_ cannot be empty"),
      );

      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, "")).to.be.revertedWith(
        unacceptable("symbol_ cannot be empty"),
      );

      // empty genesis rules
      const universeRule = "0x0000000000000000000000000000000000000000000000000000000000000001";
      const emptyRule = "0x0000000000000000000000000000000000000000000000000000000000000002";

      const { _policyManager, _mockERC20 } = await mockInvalidRuleRegistry(NULL_BYTES32, emptyRule);

      config = {
        ...config,
        policyManager: _policyManager.address,
        collateralToken: _mockERC20.address,
      };

      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("the universe rule is not defined in the PolicyManager's RuleRegistry"),
      );

      const { _policyManager: __policyManager, _mockERC20: __mockERC20 } = await mockInvalidRuleRegistry(
        universeRule,
        NULL_BYTES32,
      );

      config = {
        ...config,
        policyManager: __policyManager.address,
        collateralToken: __mockERC20.address,
      };

      await expect(deployKycERC20(config, 0, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("the empty rule is not defined in the PolicyManager's RuleRegistry"),
      );

      // admissionPolicy is disabled
      config = {
        ...config,
        policyManager: policyManager.address,
        collateralToken: mockERC20.address,
      };
      const admissionPolicyId = 1;
      const now = await helpers.time.latest();
      const deadline = now + THIRTY_DAYS_IN_SECONDS + 1000;
      await policyManager.removePolicyAttestors(admissionPolicyId, [attestor1, attestor2], deadline);
      await helpers.time.increase(policyDisablementPeriod + 1000);
      await policyManager.disablePolicy(admissionPolicyId);
      await expect(
        deployKycERC20(config, admissionPolicyId, MAXIMUM_CONSENT_PERIOD, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("admissionPolicy is disabled"));
    });

    it("should be configured", async function () {
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      config = {
        ...config,
        collateralToken: mockERC20.address,
        policyManager: policyManager.address,
        userPolicies: userPolicies.address,
      };

      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
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
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };
      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      // check isAuthorized (compliant)
      expect(await kycERC20.callStatic.isAuthorized(trader0.address, trader1.address)).to.be.equal(true);
      expect(await kycERC20.callStatic.isAuthorized(trader1.address, trader1.address)).to.be.equal(true);

      const kycERC20WithTrader = kycERC20.connect(traderAsSigner1);

      await expect(kycERC20WithTrader.depositFor(trader1.address, 100)).to.be.revertedWith(errorAllowance);
      await expect(kycERC20WithTrader.transferFrom(trader1.address, trader1.address, 100)).to.be.revertedWith(
        errorAllowance,
      );

      await mockERC20.connect(traderAsSigner1).approve(kycERC20.address, 100);
      expect(await mockERC20.allowance(trader1.address, kycERC20.address)).to.be.equal("100");
      await expect(kycERC20WithTrader.depositFor(trader1.address, 100)).to.be.revertedWith(errorBalanceTransfer);

      await expect(kycERC20WithTrader.withdrawTo(trader1.address, 100)).to.be.revertedWith(errorBalanceBurn);
    });

    it("should depositFor and withdrawTo kycERC20", async function () {
      const mockERC20 = await deployMockERC20(traderAsSigner1);
      await mockERC20.deployed();

      const admissionPolicyId = 1;
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };
      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner1,
      );

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(trader1.address, 100);

      let kycBalance = await kycERC20.balanceOf(trader1.address);
      let contractMockBalance = await mockERC20.balanceOf(kycERC20.address);
      let senderMockBalance = await mockERC20.balanceOf(trader1.address);
      expect(kycBalance.toString()).to.equal("100");
      expect(contractMockBalance).to.equal("100");
      expect(senderMockBalance.toString()).to.equal("9900");

      await kycERC20.approve(kycERC20.address, 50);
      await kycERC20.withdrawTo(trader1.address, 50);

      kycBalance = await kycERC20.balanceOf(trader1.address);
      contractMockBalance = await mockERC20.balanceOf(kycERC20.address);
      senderMockBalance = await mockERC20.balanceOf(trader1.address);
      expect(kycBalance.toString()).to.equal("50");
      expect(contractMockBalance).to.equal("50");
      expect(senderMockBalance.toString()).to.equal("9950");

      // should allow non-compliant trader to depositFor/withdrawTo for himself, but not to a third
      const amount = TOKEN_SUPPLY / 10;
      await mockERC20.transfer(admin, amount);
      await mockERC20.connect(adminWallet).approve(kycERC20.address, amount);
      await expect(kycERC20.connect(adminWallet).depositFor(bob, amount)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );
      await kycERC20.connect(adminWallet).depositFor(admin, amount);
      await expect(kycERC20.withdrawTo(bob, amount)).to.be.revertedWith(unacceptable("trader not authorized"));
      await kycERC20.connect(adminWallet).withdrawTo(admin, amount);
    });

    it("should not allow a transfer to a non-compliant wallet", async function () {
      const admissionPolicyId = 1;

      let mockERC20 = await deployMockERC20(traderAsSigner1);
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };
      let kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner1,
      );

      await mockERC20.approve(kycERC20.address, 200);
      await kycERC20.depositFor(trader1.address, 100);

      // TO address is not compliant
      await expect(kycERC20.transfer(aliceWallet.address, 50)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );
      await expect(kycERC20.depositFor(aliceWallet.address, 50)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );
      await expect(kycERC20.withdrawTo(aliceWallet.address, 50)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );

      mockERC20 = await deployMockERC20(aliceWallet);
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };
      kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        aliceWallet,
      );

      await mockERC20.transfer(aliceWallet.address, 100);
      await mockERC20.connect(aliceWallet).approve(kycERC20.address, 100);
      await kycERC20.connect(aliceWallet).depositFor(aliceWallet.address, 100);

      // FROM address is not compliant
      await expect(kycERC20.connect(aliceWallet).transfer(trader0.address, 50)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );
    });

    it("should allow a transfer to a compliant wallet", async function () {
      const mockERC20 = await deployMockERC20(traderAsSigner0);

      const admissionPolicyId = 1;
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };
      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner0,
      );

      await mockERC20.approve(kycERC20.address, 105);
      await kycERC20.depositFor(trader0.address, 100);
      await kycERC20.transfer(trader1.address, 40);

      let kycBalanceTrader0 = await kycERC20.balanceOf(trader0.address);
      let kycBalanceTrader1 = await kycERC20.balanceOf(trader1.address);
      expect(kycBalanceTrader0).to.equal("60");
      expect(kycBalanceTrader1).to.equal("40");

      await kycERC20.connect(traderAsSigner1).approve(trader1.address, 25);
      await kycERC20.connect(traderAsSigner1).transferFrom(trader1.address, trader0.address, 25);

      await kycERC20.withdrawTo(trader1.address, 5);
      await kycERC20.depositFor(trader1.address, 5);

      kycBalanceTrader0 = await kycERC20.balanceOf(trader0.address);
      kycBalanceTrader1 = await kycERC20.balanceOf(trader1.address);
      expect(kycBalanceTrader0).to.equal("80");
      expect(kycBalanceTrader1).to.equal("20");

      // both addresses needs to be compliant
      const whitelistTime = await helpers.time.latest();
      await walletCheck.setWalletCheck(aliceWallet.address, true, whitelistTime);
      await expect(kycERC20.transfer(aliceWallet.address, 50)).to.be.revertedWith(
        unacceptable("trader not authorized"),
      );
    });

    it("should not allow trading when one of both parties use the emptyRule", async function () {
      const emptyRule = await ruleRegistry.ruleAtIndex(1);

      const mockERC20 = await deployMockERC20(traderAsSigner1);
      await mockERC20.deployed();

      const emptyRulePolicyScalar = {
        ...policyScalar,
        ruleId: emptyRule,
      };

      await policyManager.createPolicy(emptyRulePolicyScalar, [identityTree.address], [walletCheck.address]);
      const emptyRulePolicy = Number(await policyManager.policyCount()) - 1;

      config = {
        ...config,
        collateralToken: mockERC20.address,
      };

      const kycERC20 = await deployKycERC20(
        config,
        emptyRulePolicy,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner1,
      );

      await userPolicies.connect(traderAsSigner1).setUserPolicy(emptyRulePolicy);

      await mockERC20.approve(kycERC20.address, 100);
      await expect(kycERC20.transfer(trader1.address, 100)).to.be.revertedWith(unacceptable("trader not authorized"));
    });

    it("should reject Policy B by wallet check whitelist check after Policy A credential is refreshed", async function () {
      // check that user has valid credential for Policy B and wallet is whitelisted in WalletCheck
      const policyA = 3;
      const policyB = 4;

      const mockERC20 = await deployMockERC20(traderAsSigner1);

      const admissionPolicyId = policyB;

      config = {
        ...config,
        collateralToken: mockERC20.address,
      };

      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner1,
      );

      await mockERC20.approve(kycERC20.address, 1000);
      await kycERC20.depositFor(trader1.address, 100);

      let kycBalanceTrader2 = await kycERC20.balanceOf(trader1.address);
      expect(kycBalanceTrader2).to.equal("100");

      // user updates credential for Policy A
      // NOTE proof incluceds Policy B as well as Policy A
      await credentialsUpdater
        .connect(traderAsSigner1)
        .updateCredentials(identityTree.address, membershipProof1, authorisationProof1);

      await kycERC20.depositFor(trader1.address, 100);
      kycBalanceTrader2 = await kycERC20.balanceOf(trader1.address);
      expect(kycBalanceTrader2).to.equal("200");
    });

    it("should allow policy admin to maintain a global list of whitelisted addresses", async function () {
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      config = {
        ...config,
        collateralToken: mockERC20.address,
      };

      const kycERC20 = await deployKycERC20(
        config,
        admissionPolicyId,
        MAXIMUM_CONSENT_PERIOD,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      // allow whitelisting
      const now = await helpers.time.latest();
      const timeToNextBlock = 1; // 1 second, because the next block is happening 1 second after now
      const deadline = now + THIRTY_DAYS_IN_SECONDS + timeToNextBlock;
      const policyObj = await policyManager.callStatic.policy(admissionPolicyId);
      expect(policyObj.config.allowApprovedCounterparties).to.be.false;
      await policyManager.updatePolicyAllowApprovedCounterparties(admissionPolicyId, true, deadline);
      await helpers.time.increaseTo(deadline);
      await policyManager.policy(admissionPolicyId);
      const newPolicyObj = await policyManager.callStatic.policy(admissionPolicyId);
      expect(newPolicyObj.config.allowApprovedCounterparties).to.be.true;

      // deposit & withdraw is not restricted
      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(admin, 100);

      // from must whitelist to & vice versa
      await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));
      await userPolicies.connect(bobAsSigner).addApprovedCounterparty(admin);
      await userPolicies.addApprovedCounterparty(bob);
      // fromIsApprovedByTo = IUserPolicies(userPolicies).isApproved(to, from);
      expect(await userPolicies.isApproved(bob, admin)).to.be.true;
      expect(await userPolicies.isApproved(admin, bob)).to.be.true;
      expect(await policyManager.policyDisabled(admissionPolicyId)).to.be.false;
      await kycERC20.transfer(bob, 40);

      const adminKycBalance = await kycERC20.balanceOf(admin);
      const bobKycBalance = await kycERC20.balanceOf(bob);
      expect(adminKycBalance.toString()).to.equal("60");
      expect(bobKycBalance.toString()).to.equal("40");
    });

    it("should not allow users to whitelist themselves", async function () {
      await expect(userPolicies.addApprovedCounterparty(admin)).to.be.revertedWith(
        unacceptable("self approving is not permitted"),
      );
    });

    describe("Exemption Manager", function () {
      it("should allow trading when both parties are exempted by the policy admin", async function () {
        const admissionPolicyId = 1;
        const mockERC20 = await deployMockERC20();
        config = {
          ...config,
          collateralToken: mockERC20.address,
        };

        const kycERC20 = await deployKycERC20(
          config,
          admissionPolicyId,
          MAXIMUM_CONSENT_PERIOD,
          TOKEN_NAME,
          TOKEN_SYMBOL,
        );

        // deposit & withdraw is not restricted
        await mockERC20.approve(kycERC20.address, 100);
        await kycERC20.depositFor(admin, 100);

        await expect(kycERC20.transfer(bob, 50)).to.be.revertedWith(unacceptable("trader not authorized"));

        const exemptions = [admin, bob];
        const description = "test exemption";
        await exemptionsManager.admitGlobalExemption(exemptions, description);
        await exemptionsManager.approvePolicyExemptions(admissionPolicyId, exemptions);

        await kycERC20.transfer(bob, 60);

        const adminKycBalance = await kycERC20.balanceOf(admin);
        const bobKycBalance = await kycERC20.balanceOf(bob);
        expect(adminKycBalance.toString()).to.equal("40");
        expect(bobKycBalance.toString()).to.equal("60");
      });
    });

    describe("Fail safe / Degraded Mode ", function () {
      it("should allow anyone to disable a failed policy", async function () {
        const admissionPolicyId = 1;

        const mockERC20 = await deployMockERC20(traderAsSigner0);
        config = {
          ...config,
          collateralToken: mockERC20.address,
        };
        const kycERC20 = await deployKycERC20(
          config,
          admissionPolicyId,
          MAXIMUM_CONSENT_PERIOD,
          TOKEN_NAME,
          TOKEN_SYMBOL,
          traderAsSigner0,
        );

        // deposit & withdraw is not restricted
        await mockERC20.approve(kycERC20.address, 100);
        await kycERC20.depositFor(trader0.address, 100);

        expect(await kycERC20.callStatic.isAuthorized(trader0.address, trader1.address)).to.be.true;
        await kycERC20.transfer(trader1.address, 60);

        // delete unused attestors
        let now = await helpers.time.latest();
        const deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
        await policyManager.removePolicyAttestors(admissionPolicyId, [attestor1, attestor2], deadline);
        await applyPolicyChanges(policyManager, admissionPolicyId);

        // check last update of walletCheck and atttestor service
        const walletCheckLastUpdate = await walletCheck.lastUpdate();
        const atttestorLastUpdate = await identityTree.lastUpdate();
        const lastUpdate = walletCheckLastUpdate > atttestorLastUpdate ? walletCheckLastUpdate : atttestorLastUpdate;

        // check for valid credentials, should be stale
        expect(await kycERC20.callStatic.isAuthorized(trader0.address, trader1.address)).to.be.false;

        // degrade service
        // isDegraded --> isIndeed =  time > lastUpdate + policyDegradationPeriod;
        // credentials.isDegraded(admissionPolicyId);
        now = await helpers.time.latest();

        policyDisablementPeriod; // 42 days
        defaultDegradationPeriod; // 7 days
        defaultFreshnessPeriod; // 30 days
        const degradationFreshnessPeriod = ONE_DAY_IN_SECONDS * 40; // 40 days

        expect(await credentials.degradationPeriod(admissionPolicyId)).to.be.equal(defaultDegradationPeriod);
        await credentials.setPolicyParameters(admissionPolicyId, defaultDegradationPeriod, degradationFreshnessPeriod);

        // user gives consent to degraded credentials and walletCheck service
        const revocationDeadline = now + MAXIMUM_CONSENT_PERIOD;
        await credentials.connect(traderAsSigner0).grantDegradedServiceConsent(revocationDeadline);
        await credentials.connect(traderAsSigner1).grantDegradedServiceConsent(revocationDeadline);
        await walletCheck.connect(traderAsSigner0).grantDegradedServiceConsent(revocationDeadline);
        await walletCheck.connect(traderAsSigner1).grantDegradedServiceConsent(revocationDeadline);

        // allow mitigation -> test trade with consent
        expect(await credentials.isDegraded(admissionPolicyId)).to.be.true;
        const keyGen = await credentials.keyGen(trader0.address, admissionPolicyId);
        expect(await credentials.isMitigationQualified(keyGen, admissionPolicyId)).to.be.true;
        expect(await credentials.canMitigate(trader1.address, keyGen, admissionPolicyId)).to.be.true;
        expect(await kycERC20.callStatic.isAuthorized(trader0.address, trader1.address)).to.be.true;
        await kycERC20.transfer(trader1.address, 20);

        // policyCanBeDisabled
        await expect(policyManager.connect(traderAsSigner0).disablePolicy(admissionPolicyId)).to.be.revertedWith(
          unacceptable("only failed policies can be disabled"),
        );
        const policyFailedTime = lastUpdate.toNumber() + policyDisablementPeriod + 1;
        await helpers.time.increaseTo(policyFailedTime);
        expect(await policyManager.callStatic.policyCanBeDisabled(admissionPolicyId)).to.be.true;

        // disable policy -> test trade with consent
        await policyManager.connect(traderAsSigner0).disablePolicy(admissionPolicyId);
        await expect(policyManager.connect(traderAsSigner0).disablePolicy(admissionPolicyId)).revertedWith(
          unacceptable("policy is already disabled"),
        );

        await kycERC20.grantDegradedServiceConsent(revocationDeadline);
        expect(await kycERC20.callStatic.isAuthorized(trader1.address, trader0.address)).to.be.false;
        await kycERC20.connect(traderAsSigner1).grantDegradedServiceConsent(revocationDeadline);
        await kycERC20.transfer(trader1.address, 20);

        // disabling default policy should not be possible
        await expect(policyManager.connect(traderAsSigner0).disablePolicy(0)).to.be.revertedWith(
          unacceptable("cannot disable the default policy"),
        );
      });

      it("should allow a user to grant and revoke consent for degraded services", async () => {
        let now = await helpers.time.latest();
        const maximumConsentPeriod = await credentials.maximumConsentPeriod();

        const revocationDeadline = now + maximumConsentPeriod.toNumber();
        await credentials.grantDegradedServiceConsent(revocationDeadline);

        const revocationDeadlineTooEarly = now - 1;
        await expect(credentials.grantDegradedServiceConsent(revocationDeadlineTooEarly)).to.be.revertedWith(
          unacceptable("revocation deadline cannot be in the past"),
        );

        now = await helpers.time.latest();
        const revocationDeadlineTooLate = now + maximumConsentPeriod.toNumber() + 2;
        await expect(credentials.grantDegradedServiceConsent(revocationDeadlineTooLate)).to.be.revertedWith(
          unacceptable("revocation deadline is too far in the future"),
        );

        expect((await credentials.userConsentDeadlines(admin)).toNumber()).to.be.equal(revocationDeadline);
        expect(await credentials.userConsentsToMitigation(admin)).to.be.true;

        await credentials.revokeMitigationConsent();
        expect((await credentials.userConsentDeadlines(admin)).toNumber()).to.be.equal(0);
        expect(await credentials.userConsentsToMitigation(admin)).to.be.false;
      });

      it("should not allow to disabled policy with an unused services", async () => {
        // No evidence of interrupted activity yet

        // new attestor with no activity
        const IdentityTree = (await ethers.getContractFactory("IdentityTree")) as IdentityTree__factory;
        const newAttestor = (await IdentityTree.deploy(
          forwarder.address,
          policyManager.address,
          MAXIMUM_CONSENT_PERIOD,
        )) as IdentityTree;
        await newAttestor.deployed();
        await policyManager.admitAttestor(newAttestor.address, "inactive attestation service");

        // new wallet check service with no activity
        const WalletCheck = (await ethers.getContractFactory("WalletCheck")) as WalletCheck__factory;
        const newWalletCheck = (await WalletCheck.deploy(
          forwarder.address,
          policyManager.address,
          MAXIMUM_CONSENT_PERIOD,
          "inactive wallet check service",
        )) as WalletCheck;
        await newWalletCheck.deployed();
        await policyManager.admitWalletCheck(newWalletCheck.address);

        await policyManager.createPolicy(policyScalar, [newAttestor.address], [newWalletCheck.address]);
        const policyCount = await policyManager.policyCount();
        expect(await policyManager.callStatic.policyCanBeDisabled(policyCount.sub(1))).to.be.equal(false);

        // And services are also not degraded
        expect(await newAttestor.isDegraded(policyCount.sub(1))).to.be.equal(false);
        expect(await newWalletCheck.isDegraded(policyCount.sub(1))).to.be.equal(false);
        expect(await newAttestor.mitigationCutoff(policyCount.sub(1))).to.be.equal(await helpers.time.latest());

        // But only if both services are unused
        const ROLE_WALLETCHECK_LIST_ADMIN = await newWalletCheck.ROLE_WALLETCHECK_LIST_ADMIN();
        await newWalletCheck.grantRole(ROLE_WALLETCHECK_LIST_ADMIN, admin);
        const whitelistTime = await helpers.time.latest();
        await newWalletCheck.setWalletCheck(admin, true, whitelistTime);
        await helpers.time.increase(policyDisablementPeriod + 1000);
        expect(await policyManager.callStatic.policyCanBeDisabled(policyCount.sub(1))).to.be.equal(true);
      });

      it("should not return a degration period or freshness period for a non-existent policy", async () => {
        await expect(walletCheck.callStatic.degradationPeriod(100)).to.be.revertedWith("unknown policy");
        await expect(walletCheck.callStatic.degradationFreshness(100)).to.be.revertedWith("unknown policy");
      });
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

const deployKycERC20 = async function (
  config: IKeyringGuard.KeyringConfigStruct,
  policyId: number,
  MAXIMUM_CONSENT_PERIOD: number,
  name: string,
  symbol: string,
  deployer?: Signer,
) {
  const kycERC20Factory = (await ethers.getContractFactory("KycERC20")) as KycERC20__factory;

  const kycERC20 = (
    deployer
      ? await kycERC20Factory.connect(deployer).deploy(config, policyId, MAXIMUM_CONSENT_PERIOD, name, symbol)
      : await kycERC20Factory.deploy(config, policyId, MAXIMUM_CONSENT_PERIOD, name, symbol)
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

// TODO put into utils file
const walletCheckKeyGen = (subject: string) => {
  const subjectBN = ethers.BigNumber.from(subject);
  const subjectBytes32 = ethers.utils.hexZeroPad(subjectBN.toHexString(), 32);
  return subjectBytes32;
};

const applyPolicyChanges = async (policyManager: PolicyManager, policyId: number) => {
  const policyObj = await policyManager.callStatic.policy(policyId);
  await helpers.time.increaseTo(policyObj.deadline.toNumber());
  await policyManager.policy(policyId);
};
