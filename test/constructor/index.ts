import { createFixtureLoader } from "ethereum-waffle";
import { ethers, waffle } from "hardhat";
import { expect } from "chai";
import { keyringTestFixture } from "../shared/fixtures";
import type {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  NoImplementation,
  KeyringZkVerifier,
  KeyringCredentials__factory,
  KeyringZkCredentialUpdater__factory,
  PolicyStorage__factory,
  PolicyManager__factory,
  RuleRegistry__factory,
  UserPolicies__factory,
  KeyringZkVerifier__factory,
  WalletCheck__factory,
  IdentityTree__factory,
  ExemptionsManager,
  ExemptionsManager__factory,
  KeyringMerkleAuthZkCredentialUpdater__factory,
  KeyringMerkleAuthZkVerifier__factory,
} from "../../src/types";
import { namedAccounts, genesis, NULL_ADDRESS, MAXIMUM_CONSENT_PERIOD, MINIMUM_MAX_CONSENT_PERIOD } from "../constants";
import { unacceptable } from "../helpers";

describe("General", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];

  // prepare contracts with interfaces
  let credentials: KeyringCredentials;
  let ruleRegistry: RuleRegistry;
  let policyManager: PolicyManager;
  let forwarder: NoImplementation;
  let keyringZkVerifier: KeyringZkVerifier;
  let exemptionsManager: ExemptionsManager;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  before(async () => {
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);

    const fixture = await loadFixture(keyringTestFixture);
    credentials = fixture.contracts.credentials;
    ruleRegistry = fixture.contracts.ruleRegistry;
    policyManager = fixture.contracts.policyManager;
    forwarder = fixture.contracts.forwarder;
    keyringZkVerifier = fixture.contracts.keyringZkVerifier;
    exemptionsManager = fixture.contracts.exemptionsManager;
  });

  describe("Constructor & Init Requirements", function () {
    it("should not deploy if constructor inputs are empty", async function () {
      const CredentialsFactory = (await ethers.getContractFactory("KeyringCredentials")) as KeyringCredentials__factory;
      await expect(
        CredentialsFactory.deploy(NULL_ADDRESS, policyManager.address, MAXIMUM_CONSENT_PERIOD),
      ).to.be.revertedWith(unacceptable("trustedForwarder cannot be empty"));
      await expect(
        CredentialsFactory.deploy(forwarder.address, NULL_ADDRESS, MAXIMUM_CONSENT_PERIOD),
      ).to.be.revertedWith(unacceptable("policyManager_ cannot be empty"));

      const CredentialsUpdaterFactory = (await ethers.getContractFactory(
        "KeyringZkCredentialUpdater",
      )) as KeyringZkCredentialUpdater__factory;

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

      const PolicyStorageFactory = (await ethers.getContractFactory("PolicyStorage")) as PolicyStorage__factory;
      const PolicyStorage = await PolicyStorageFactory.deploy();
      await PolicyStorage.deployed();
      const PolicyManagerFactory = (await ethers.getContractFactory("PolicyManager", {
        libraries: {
          PolicyStorage: PolicyStorage.address,
        },
      })) as PolicyManager__factory;
      await expect(PolicyManagerFactory.deploy(NULL_ADDRESS, ruleRegistry.address)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );
      await expect(PolicyManagerFactory.deploy(forwarder.address, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("ruleRegistry cannot be empty"),
      );

      const RuleRegistryFactory = (await ethers.getContractFactory("RuleRegistry")) as RuleRegistry__factory;
      await expect(RuleRegistryFactory.deploy(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );

      const UserPoliciesFactory = (await ethers.getContractFactory("UserPolicies")) as UserPolicies__factory;
      await expect(UserPoliciesFactory.deploy(NULL_ADDRESS, policyManager.address)).to.be.revertedWith(
        unacceptable("trustedForwarder cannot be empty"),
      );
      await expect(UserPoliciesFactory.deploy(forwarder.address, NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("policyManager cannot be empty"),
      );

      const KeyringZkVerifierFactory = (await ethers.getContractFactory(
        "KeyringZkVerifier",
      )) as KeyringZkVerifier__factory;
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

      const WalletCheckFactory = (await ethers.getContractFactory("WalletCheck")) as WalletCheck__factory;
      const walletCheckUri = "https://keyring.network/walletchecker1";
      await expect(
        WalletCheckFactory.deploy(NULL_ADDRESS, policyManager.address, MAXIMUM_CONSENT_PERIOD, walletCheckUri),
      ).to.be.revertedWith(unacceptable("trustedForwarder cannot be empty"));
      await expect(
        WalletCheckFactory.deploy(forwarder.address, policyManager.address, MAXIMUM_CONSENT_PERIOD, ""),
      ).to.be.revertedWith(unacceptable("uri_ cannot be empty"));
      await expect(
        WalletCheckFactory.deploy(forwarder.address, NULL_ADDRESS, MAXIMUM_CONSENT_PERIOD, walletCheckUri),
      ).to.be.revertedWith(unacceptable("policyManager_ cannot be empty"));
      const invalidConsentPeriod = MINIMUM_MAX_CONSENT_PERIOD - 1;
      await expect(
        WalletCheckFactory.deploy(forwarder.address, policyManager.address, invalidConsentPeriod, walletCheckUri),
      ).to.be.revertedWith(unacceptable("The maximum consent period must be at least 1 hour"));

      const IdentityTreeFactory = (await ethers.getContractFactory("IdentityTree")) as IdentityTree__factory;
      await expect(
        IdentityTreeFactory.deploy(NULL_ADDRESS, policyManager.address, MAXIMUM_CONSENT_PERIOD),
      ).to.be.revertedWith(unacceptable("trustedForwarder cannot be empty"));
      await expect(
        IdentityTreeFactory.deploy(forwarder.address, NULL_ADDRESS, MAXIMUM_CONSENT_PERIOD),
      ).to.be.revertedWith(unacceptable("policyManager_ cannot be empty"));

      const KeyringMerkleAuthZkCredentialUpdaterFactory = (await ethers.getContractFactory(
        "KeyringMerkleAuthZkCredentialUpdater",
      )) as KeyringMerkleAuthZkCredentialUpdater__factory;
      await expect(
        IdentityTreeFactory.deploy(NULL_ADDRESS, policyManager.address, MAXIMUM_CONSENT_PERIOD),
      ).to.be.revertedWith(unacceptable("trustedForwarder cannot be empty"));
      await expect(
        KeyringMerkleAuthZkCredentialUpdaterFactory.deploy(
          NULL_ADDRESS,
          credentials.address,
          policyManager.address,
          keyringZkVerifier.address,
        ),
      ).to.be.revertedWith(unacceptable("trustedForwarder cannot be empty"));
      await expect(
        KeyringMerkleAuthZkCredentialUpdaterFactory.deploy(
          forwarder.address,
          NULL_ADDRESS,
          policyManager.address,
          keyringZkVerifier.address,
        ),
      ).to.be.revertedWith(unacceptable("keyringCredentials cannot be empty"));
      await expect(
        KeyringMerkleAuthZkCredentialUpdaterFactory.deploy(
          forwarder.address,
          credentials.address,
          NULL_ADDRESS,
          keyringZkVerifier.address,
        ),
      ).to.be.revertedWith(unacceptable("policyManager cannot be empty"));
      await expect(
        KeyringMerkleAuthZkCredentialUpdaterFactory.deploy(
          forwarder.address,
          credentials.address,
          policyManager.address,
          NULL_ADDRESS,
        ),
      ).to.be.revertedWith(unacceptable("keyringMerkleAuthZkVerifier cannot be empty"));

      const KeyringMerkleAuthZkVerifier = (await ethers.getContractFactory(
        "KeyringMerkleAuthZkVerifier",
      )) as KeyringMerkleAuthZkVerifier__factory;
      await expect(KeyringMerkleAuthZkVerifier.deploy(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("merkleAuthProofVerifier cannot be empty"),
      );
    });

    it("should not allow to init if inputs are empty", async function () {
      const RuleRegistryFactory = (await ethers.getContractFactory("RuleRegistry")) as RuleRegistry__factory;
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

      // policyManager_ cannot be empty
      const ExemptionsManager = (await ethers.getContractFactory("ExemptionsManager")) as ExemptionsManager__factory;
      exemptionsManager = (await ExemptionsManager.deploy(forwarder.address)) as ExemptionsManager;
      await expect(exemptionsManager.init(NULL_ADDRESS)).to.be.revertedWith(
        unacceptable("policyManager_ cannot be empty"),
      );
    });
  });
});
