import { upgradeContract } from "../../deploy/helpers";
import { createFixtureLoader } from "ethereum-waffle";
import { ethers, waffle } from "hardhat";
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
  ExemptionsManager,
  ConstructionVerifier,
  AuthorizationVerifier,
  MembershipVerifier20,
} from "../../src/types";
import { MAXIMUM_CONSENT_PERIOD, namedAccounts } from "../constants";
import { expect } from "chai";

describe("Upgrade Helper", () => {
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
  let exemptionsManager: ExemptionsManager;
  let identityConstructionProofVerifier: ConstructionVerifier;
  let authorizationProofVerifier: AuthorizationVerifier;
  let identityMembershipProofVerifier: MembershipVerifier20;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  before(async () => {
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

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
    exemptionsManager = fixture.contracts.exemptionsManager;
    identityConstructionProofVerifier = fixture.contracts.identityConstructionProofVerifier;
    authorizationProofVerifier = fixture.contracts.authorizationProofVerifier;
    identityMembershipProofVerifier = fixture.contracts.identityMembershipProofVerifier;
  });

  it("should upgrade KeyringCredentials", async () => {
    const proxyAddress = credentials.address;
    console.log("Credentials Proxy address:", proxyAddress);
    const constructorArgs = [forwarder.address, policyManager.address, MAXIMUM_CONSENT_PERIOD];
    await upgradeContract(ethers, "KeyringCredentials", proxyAddress, constructorArgs);
    expect(await credentials.isTrustedForwarder(forwarder.address)).to.equal(true);
    expect(await credentials.policyManager()).to.equal(policyManager.address);
    expect(await credentials.maximumConsentPeriod()).to.equal(MAXIMUM_CONSENT_PERIOD);
  });

  it("should upgrade RuleRegistry", async () => {
    const proxyAddress = ruleRegistry.address;
    console.log("RuleRegistry Proxy address:", proxyAddress);
    const constructorArgs = [forwarder.address];
    await upgradeContract(ethers, "RuleRegistry", proxyAddress, constructorArgs);
    expect(await ruleRegistry.isTrustedForwarder(forwarder.address)).to.equal(true);
  });

  it("should upgrade UserPolicies", async () => {
    const proxyAddress = userPolicies.address;
    console.log("UserPolicies Proxy address:", proxyAddress);
    const constructorArgs = [forwarder.address, policyManager.address];
    await upgradeContract(ethers, "UserPolicies", proxyAddress, constructorArgs);
    expect(await userPolicies.isTrustedForwarder(forwarder.address)).to.equal(true);
    expect(await userPolicies.policyManager()).to.equal(policyManager.address);
  });

  it("should upgrade PolicyManager", async () => {
    const proxyAddress = policyManager.address;
    console.log("PolicyManager Proxy address:", proxyAddress);
    const constructorArgs = [forwarder.address, ruleRegistry.address];
    const libraries = ["PolicyStorage"];
    await upgradeContract(ethers, "PolicyManager", proxyAddress, constructorArgs, libraries);
    expect(await policyManager.isTrustedForwarder(forwarder.address)).to.equal(true);
    expect(await policyManager.ruleRegistry()).to.equal(ruleRegistry.address);
  });

  it("should upgrade forwarder", async () => {
    const proxyAddress = forwarder.address;
    console.log("Forwarder Proxy address:", proxyAddress);
    const constructorArgs: any = [];
    await upgradeContract(ethers, "NoImplementation", proxyAddress, constructorArgs);
  });

  it("should upgrade KeyringZkVerifier", async () => {
    const proxyAddress = keyringZkVerifier.address;
    console.log("KeyringZkVerifier Proxy address:", proxyAddress);
    const constructorArgs = [
      identityConstructionProofVerifier.address,
      identityMembershipProofVerifier.address,
      authorizationProofVerifier.address,
    ];
    await upgradeContract(ethers, "KeyringZkVerifier", proxyAddress, constructorArgs);
    expect(await keyringZkVerifier.IDENTITY_CONSTRUCTION_PROOF_VERIFIER()).to.equal(
      identityConstructionProofVerifier.address,
    );
    expect(await keyringZkVerifier.IDENTITY_MEMBERSHIP_PROOF_VERIFIER()).to.equal(
      identityMembershipProofVerifier.address,
    );
    expect(await keyringZkVerifier.AUTHORIZATION_PROOF_VERIFIER()).to.equal(authorizationProofVerifier.address);
  });

  // Contracts below are not upgradeable

  /*
    it("should upgrade WalletCheck", async () => {
        const proxyAddress = walletCheck.address;
        console.log('WalletCheck Proxy address:', proxyAddress);
        const constructorArgs = [forwarder.address, policyManager.address, MAXIMUM_CONSENT_PERIOD, "some uri"];
        await upgradeContract(ethers, "WalletCheck", proxyAddress, constructorArgs);
        expect(await walletCheck.isTrustedForwarder(forwarder.address)).to.equal(true);
        expect(await walletCheck.policyManager()).to.equal(policyManager.address);
        expect(await walletCheck.maximumConsentPeriod()).to.equal(MAXIMUM_CONSENT_PERIOD);
    });

    it("should upgrade IdentityTree", async () => {
        const proxyAddress = identityTree.address;
        console.log('IdentityTree Proxy address:', proxyAddress);
        const constructorArgs = [forwarder.address, policyManager.address, MAXIMUM_CONSENT_PERIOD];
        await upgradeContract(ethers, "IdentityTree", proxyAddress, constructorArgs);
        expect(await identityTree.isTrustedForwarder(forwarder.address)).to.equal(true);
        expect(await identityTree.policyManager()).to.equal(policyManager.address);
        expect(await identityTree.maximumConsentPeriod()).to.equal(MAXIMUM_CONSENT_PERIOD);
    });
    
    it("should upgrade ExemptionsManager", async () => {
        const proxyAddress = exemptionsManager.address;
        console.log('ExemptionsManager Proxy address:', proxyAddress);
        const constructorArgs = [forwarder.address];
        await upgradeContract(ethers, "ExemptionsManager", proxyAddress, constructorArgs);
        expect(await exemptionsManager.isTrustedForwarder(forwarder.address)).to.equal(true);
    });
    */
});
