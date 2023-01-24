import { Signer, Wallet } from "ethers";
import { getNamedAccounts, ethers, waffle, upgrades } from "hardhat";
import { createFixtureLoader } from "ethereum-waffle";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { keyringTestFixture } from "../shared/fixtures";
import _RuleRegistry from "../../artifacts/contracts/ruleRegistry/RuleRegistry.sol/RuleRegistry.json";
import type {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  KeyringZkCredentialUpdater,
  WalletCheck,
  IdentityTree,
  MockERC20,
  KycERC20,
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
  let credentials: KeyringCredentials;
  let ruleRegistry: RuleRegistry;
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
  let traderAsSigner2: Signer;
  let traderAsSigner3: Signer;

  before(async () => {
    const { admin: adminAddress } = await getNamedAccounts();
    admin = adminAddress;
    // set up trader wallets with 2000 ETH each
    traderAsSigner2 = new Wallet(trader2.priv, provider);
    traderAsSigner3 = new Wallet(trader3.priv, provider);
    await adminWallet.sendTransaction({ to: trader2.address, value: ethers.utils.parseEther("2000") });
    await adminWallet.sendTransaction({ to: trader3.address, value: ethers.utils.parseEther("2000") });

    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  describe("kycERC20", function () {
    beforeEach(async function () {
      // load pre-configured contracts
      const fixture = await loadFixture(keyringTestFixture);
      credentials = fixture.contracts.credentials;
      ruleRegistry = fixture.contracts.ruleRegistry;
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

    it("should not permit deployment of an invalid configuration", async function () {
      const mockERC20 = await deployMockERC20();

      const nullCredentials = (await ethers.getContractAt("KeyringCredentials", NULL_ADDRESS)) as KeyringCredentials;
      await expect(
        deployKycERC20(mockERC20, nullCredentials, policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("credentials cannot be empty"));

      const nullPolicyManager = (await ethers.getContractAt("PolicyManager", NULL_ADDRESS)) as PolicyManager;
      await expect(
        deployKycERC20(mockERC20, credentials, nullPolicyManager, await 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("policyManager cannot be empty"));

      await expect(
        deployKycERC20(mockERC20, credentials, policyManager, 99, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("admissionPolicyId not found"));

      const nullCollateral = (await ethers.getContractAt("MockERC20", NULL_ADDRESS)) as MockERC20;
      await expect(
        deployKycERC20(nullCollateral, credentials, policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("collateral token cannot be empty"));

      await expect(deployKycERC20(mockERC20, credentials, policyManager, 0, "", TOKEN_SYMBOL)).to.be.revertedWith(
        unacceptable("name_ cannot be empty"),
      );

      await expect(deployKycERC20(mockERC20, credentials, policyManager, 0, TOKEN_NAME, "")).to.be.revertedWith(
        unacceptable("symbol_ cannot be empty"),
      );

      // empty genesis rules
      const universeRule = "0x0000000000000000000000000000000000000000000000000000000000000001";
      const emptyRule = "0x0000000000000000000000000000000000000000000000000000000000000002";

      const { _policyManager, _mockERC20 } = await mockInvalidRuleRegistry(NULL_BYTES32, emptyRule);

      await expect(
        deployKycERC20(_mockERC20, credentials, _policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("the universe rule is not defined in the PolicyManager's RuleRegistry"));

      const { _policyManager: __policyManager, _mockERC20: __mockERC20 } = await mockInvalidRuleRegistry(
        universeRule,
        NULL_BYTES32,
      );

      await expect(
        deployKycERC20(__mockERC20, credentials, __policyManager, 0, TOKEN_NAME, TOKEN_SYMBOL),
      ).to.be.revertedWith(unacceptable("the empty rule is not defined in the PolicyManager's RuleRegistry"));
    });

    it("should be configured", async function () {
      const admissionPolicyId = 1;
      const mockERC20 = await deployMockERC20();
      const kycERC20 = await deployKycERC20(
        mockERC20,
        credentials,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      const credentialsAddress = await kycERC20.getKeyringCredentials();
      const policyManagerAddress = await kycERC20.getKeyringPolicyManager();
      const policyId = await kycERC20.getKeyringAdmissionPolicyId();
      const getTokenDecimals = await kycERC20.decimals();
      const getTokenName = await kycERC20.name();
      const getTokenSymbol = await kycERC20.symbol();
      const tokenGenesis = await kycERC20.getKeyringGenesisRules();

      expect(credentialsAddress).to.be.equal(credentials.address);
      expect(policyManagerAddress).to.be.equal(policyManager.address);
      expect(policyId).to.be.equal(admissionPolicyId);
      expect(getTokenDecimals.toString()).to.equal("18");
      expect(getTokenName).to.equal(TOKEN_NAME);
      expect(getTokenSymbol).to.equal(TOKEN_SYMBOL);
      expect(tokenGenesis.universeRuleId).to.equal(await ruleRegistry.ruleAtIndex(0));
      expect(tokenGenesis.emptyRuleId).to.equal(await ruleRegistry.ruleAtIndex(1));
    });

    it("should meet the ERC20 transfer and transferFrom requirements", async function () {
      const errorAllowance = "ERC20: insufficient allowance";
      const errorBalanceTransfer = "ERC20: transfer amount exceeds balance";
      const errorBalanceBurn = "ERC20: burn amount exceeds balance";

      const mockERC20 = await deployMockERC20();
      await mockERC20.deployed();
      const admissionPolicyId = 1;
      const kycERC20 = await deployKycERC20(
        mockERC20,
        credentials,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );

      // check isCompliant
      expect(await kycERC20.callStatic.checkKeyringCompliance(trader2.address)).to.be.equal(true);

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
        mockERC20,
        credentials,
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
        mockERC20,
        credentials,
        policyManager,
        admissionPolicyId,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await mockERC20.approve(kycERC20.address, 100);
      await kycERC20.depositFor(trader2.address, 100);

      await expect(kycERC20.transfer(aliceWallet.address, 50)).to.be.revertedWith("stale credential or no credential");
    });

    it("should allow a transfer to a compliant wallet", async function () {
      const mockERC20 = await deployMockERC20(traderAsSigner2);

      const admissionPolicyId = 1;

      const kycERC20 = await deployKycERC20(
        mockERC20,
        credentials,
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
        mockERC20,
        credentials,
        policyManager,
        universeRulePolicy,
        TOKEN_NAME,
        TOKEN_SYMBOL,
      );
      await kycERC20.getKeyringGenesisRules();

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
        mockERC20,
        credentials,
        policyManager,
        emptyRulePolicy,
        TOKEN_NAME,
        TOKEN_SYMBOL,
        traderAsSigner2,
      );

      await policyManager.connect(traderAsSigner2).setUserPolicy(emptyRulePolicy);

      await mockERC20.approve(kycERC20.address, 100);
      await expect(kycERC20.depositFor(trader2.address, 100)).to.be.revertedWith("stale credential or no credential");
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
          .deploy(collateral.address, credentials.address, policyManager.address, policyId, name, symbol)
      : await kycERC20Factory.deploy(
          collateral.address,
          credentials.address,
          policyManager.address,
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
