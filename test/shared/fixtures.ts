import { getNamedAccounts, ethers, upgrades } from "hardhat";
import { Fixture } from "ethereum-waffle";

import {
  KeyringCredentials,
  RuleRegistry,
  PolicyManager,
  KeyringV1CredentialUpdater,
  NoImplementation,
} from "../../src/types";

import { genesis } from "../../constants";

/********************************************
 * See project documentation for details
 * about silenced hardhat-upgrades warnings.
 * Uncomment next line to reveal warnings.
 ********************************************/

upgrades.silenceWarnings();

interface KeyringFixture {
  credentials: KeyringCredentials;
  ruleRegistry: RuleRegistry;
  policyManager: PolicyManager;
  credentialsUpdater: KeyringV1CredentialUpdater;
  forwarder: NoImplementation;
}

async function keyringFixture(): Promise<KeyringFixture> {
  const { admin } = await getNamedAccounts();

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

  /**
   * The credential credentials holds timestamps of user/policy credentials.
   * This stateful contract is upgradeable.
   */

  const CredentialsFactory = await ethers.getContractFactory("KeyringCredentials");
  const credentials = (await upgrades.deployProxy(CredentialsFactory, {
    constructorArgs: [forwarder.address],
    unsafeAllow: ["constructor", "delegatecall"],
  })) as KeyringCredentials;
  await credentials.deployed();
  await credentials.init();

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
  await ruleRegistry.init(
    genesis.universeDescription,
    genesis.universeUri,
    genesis.emptyDescription,
    genesis.emptyUri
  );

  /**
   * The policy manager holds:
   * - a whitelist of Verifiers admitted into the system by the global admin
   * - user-defined admission policies consisting of:
   *   - a rule
   *   - a minimum number of attestations required to qualify, called quorum
   *   - a time-to-live property that expires credentials
   * This stateful contract is upgradeable.
   */

  const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager");
  const policyManager = (await upgrades.deployProxy(PolicyManagerFactory, {
    constructorArgs: [forwarder.address, ruleRegistry.address],
    unsafeAllow: ["constructor", "delegatecall"],
  })) as PolicyManager;
  await policyManager.deployed();
  await policyManager.init();

  /**
   * A credential updater can write to the credential credentials, contingent on permission.
   * The credential updater verifies signature packages submitted by users against the admission rule quorum, and
   * updates the credential credentials if a minimum number of acceptable signatures are presented.
   * This stateful contract is not upgradeable. It can be replaced by:
   *  - revoking write permission in the credentials contract
   *  - assigning write permission to a new credential updater
   *  - redirecting UI submissions to a replacement credential updater with write permission.
   */

  const CredentialsUpdaterFactory = await ethers.getContractFactory("KeyringV1CredentialUpdater");
  const credentialsUpdater = (await CredentialsUpdaterFactory.deploy(
    forwarder.address,
    credentials.address,
    policyManager.address,
  )) as KeyringV1CredentialUpdater;
  await credentialsUpdater.deployed();

  const credentialsUpdaterRole = await credentials.roleCredentialsUpdater();
  const issuerAdminRole = await policyManager.roleGlobalVerifierAdmin();

  await credentials.grantRole(credentialsUpdaterRole, credentialsUpdater.address);
  await policyManager.grantRole(issuerAdminRole, admin);

  return { credentials, ruleRegistry, policyManager, credentialsUpdater, forwarder };
}

export const keyringTestFixture: Fixture<KeyringFixture> = async function (): Promise<KeyringFixture> {
  const { credentials, ruleRegistry, policyManager, credentialsUpdater, forwarder } = await keyringFixture();
  return {
    credentials,
    ruleRegistry,
    policyManager,
    credentialsUpdater,
    forwarder
  };
};
