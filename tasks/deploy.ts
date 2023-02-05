import { task } from "hardhat/config";
import { TaskArguments } from "hardhat/types";
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/dist/src/signer-with-address";

const fs = require("fs");

const timestamp = Date.now();
const contractsDir = `${__dirname}/../deploymentInfo/${timestamp}`;

import { genesis } from "../constants";

export interface Signers {
  admin: SignerWithAddress;
}

// TODO: THIS IS DEPLOYING NON-UPGRADABLE CONTRACTS. REFACTOR FOR PROXY DEPLOYMENT.

task("deploy").setAction(async function (taskArguments: TaskArguments, { ethers }) {

  /* ------------------------- Contract Data ----------------------------- */
  const IdentityConstructionProofVerifier = await import("../artifacts/contracts/zkVerifiers/identityContructionProof/contracts/IdentityConstructionProofVerifier.sol/Verifier.json");
  const AuthorizationProofVerifier = await import("../artifacts/contracts/zkVerifiers/authorizationProof/contracts/AuthorizationProofVerifier.sol/Verifier.json");
  const IdentityMembershipProofVerifier = await import("../artifacts/contracts/zkVerifiers/membershipProof/contracts/IdentityMembershipProofVerifier.sol/Verifier20.json");

  // don't need to import these as we create a factory for them
  // const IdentityTree = await import("../artifacts/contracts/identityTree/IdentityTree.sol/IdentityTree.json");
  // const PackLib = await import("../artifacts/contracts/lib/Pack12x20.sol/PackLib.json");
  // const WalletCheck = await import("../artifacts/contracts/walletCheck/WalletCheck.sol/WalletCheck.json");
  // const PolicyStorage = await import("../artifacts/contracts/lib/PolicyStorage.sol/PolicyStorage.json");
  const NoImplementation = await import("../artifacts/contracts/forwarder/NoImplementation.sol/NoImplementation.json");
  const KeyringCredentials = await import("../artifacts/contracts/keyringCredentials/KeyringCredentials.sol/KeyringCredentials.json");
  const RuleRegistry = await import("../artifacts/contracts/ruleRegistry/RuleRegistry.sol/RuleRegistry.json");
  const PolicyManager = await import("../artifacts/contracts/policyManager/PolicyManager.sol/PolicyManager.json");
  const KeyringZkCredentialUpdater = await import("../artifacts/contracts/credentialUpdater/KeyringZkCredentialUpdater.sol/KeyringZkCredentialUpdater.json");
  const KeyringZkVerifier = await import("../artifacts/contracts/keyringZkVerifier/KeyringZkVerifier.sol/KeyringZkVerifier.json");
  const UserPolicies = await import("../artifacts/contracts/userPolicies/UserPolicies.sol/UserPolicies.json");
  /* ------------------------------ Forwarder ------------------------------ */

  const signers = {} as Signers;
  const walletSigners: SignerWithAddress[] = await ethers.getSigners();
  signers.admin = walletSigners[0];
  console.log("deploying contracts");

  /* ------------------------------ Forwarder ------------------------------ */
  const ForwarderFactory = await ethers.getContractFactory("NoImplementation");
  const forwarder = await ForwarderFactory.deploy();
  console.log("Forwarder:                    ", forwarder.address);

  /* ---------------------------- KeyringZkVerifier --------------------------- */

  let verifierFactory = new ethers.ContractFactory(
    IdentityConstructionProofVerifier.abi,
    IdentityConstructionProofVerifier.bytecode,
    signers.admin,
  );
  const identityConstructionProofVerifier = await verifierFactory.deploy();
  verifierFactory = new ethers.ContractFactory(
    AuthorizationProofVerifier.abi,
    AuthorizationProofVerifier.bytecode,
    signers.admin,
  );
  const authorizationProofVerifier = await verifierFactory.deploy();

  verifierFactory = new ethers.ContractFactory(
    IdentityMembershipProofVerifier.abi,
    IdentityMembershipProofVerifier.bytecode,
    signers.admin,
  );
  const identityMembershipProofVerifier = await verifierFactory.deploy();

  const KeyringZkVerifierFactory = await ethers.getContractFactory("KeyringZkVerifier");
  const keyringZkVerifier = await KeyringZkVerifierFactory.deploy(
    identityConstructionProofVerifier.address,
    identityMembershipProofVerifier.address,
    authorizationProofVerifier.address,
  );
  console.log("KeyringZkVerifier:            ", keyringZkVerifier.address);

  /* ------------------------------ RuleRegistry ------------------------------ */
  const RuleRegistryFactory = await ethers.getContractFactory("RuleRegistry");
  const ruleRegistry = await RuleRegistryFactory.deploy(forwarder.address);
  console.log("RuleRegistry:                  ", ruleRegistry.address);

  /* ------------------------------ PolicyManager ------------------------------ */
  const PolicyStorageFactory = await ethers.getContractFactory("PolicyStorage");
  const policyStorage = await PolicyStorageFactory.deploy();
  const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager", {
    libraries: {
      PolicyStorage: policyStorage.address,
    },
  });
  const policyManager = await PolicyManagerFactory.deploy(forwarder.address, ruleRegistry.address);
  console.log("PolicyManager:                 ", policyManager.address);

  /* ------------------------------ UserPolicies ------------------------------ */
  const UserPoliciesFactory = await ethers.getContractFactory("UserPolicies");
  const userPolicies = await UserPoliciesFactory.deploy(forwarder.address, policyManager.address);
  console.log("UserPolicies:                 ", userPolicies.address);

  /* --------------------------- KeyringCredentials --------------------------- */
  const CredentialFactory = await ethers.getContractFactory("KeyringCredentials");
  const credentials = await CredentialFactory.deploy(forwarder.address, policyManager.address);
  console.log("KeyringCredentials:            ", credentials.address);

  /* ---------------------- KeyringZkCredentialUpdater ----------------------- */
  const PackLibFactory = await ethers.getContractFactory("PackLib");
  const packLib = await PackLibFactory.deploy();
  const CredentialUpdaterFactory = await ethers.getContractFactory("KeyringZkCredentialUpdater", {
    libraries: {
      PackLib: packLib.address,
    },
  });
  const credentialUpdater = await CredentialUpdaterFactory.deploy(
    forwarder.address,
    credentials.address,
    policyManager.address,
    keyringZkVerifier.address,
  );
  console.log("KeyringZkCredentialUpdater:    ", credentialUpdater.address);

  /* ------------------------------- WalletCheck ------------------------------ */
  const WalletCheckFactory = await ethers.getContractFactory("WalletCheck");
  const walletCheck = await WalletCheckFactory.deploy(forwarder.address);
  console.log("WalletCheck:                  ", walletCheck.address);

  /* ------------------------------ IdentityTree ------------------------------ */
  const IdentityTreeFactory = await ethers.getContractFactory("IdentityTree");
  const identityTree = await IdentityTreeFactory.deploy(forwarder.address);
  console.log("IdentityTree:                 ", identityTree.address);

  await forwarder.deployed();
  await identityConstructionProofVerifier.deployed();
  await authorizationProofVerifier.deployed();
  await identityMembershipProofVerifier.deployed();
  await keyringZkVerifier.deployed();
  await credentials.deployed();
  await ruleRegistry.deployed();
  await packLib.deployed();
  await policyManager.deployed();
  await userPolicies.deployed();
  await credentialUpdater.deployed();
  await policyStorage.deployed();
  await walletCheck.deployed();
  await identityTree.deployed();

  console.log("contract deployments confirmed");

  const tx1 = await credentials.init();
  await tx1.wait();
  const tx2 = await ruleRegistry.init(
    genesis.universeDescription,
    genesis.universeUri,
    genesis.emptyDescription,
    genesis.emptyUri,
  );
  await tx2.wait();
  const tx3 = await policyManager.init();
  await tx3.wait();

  console.log("contract initialization confirmed");

  /* ------------------------------ Grant Roles ------------------------------ */
  const credentialUpdaterRole = await credentials.ROLE_CREDENTIAL_UPDATER();
  const issuerAdminRole = await policyManager.ROLE_GLOBAL_ATTESTOR_ADMIN();
  const globalWalletCheckAdminRole = await policyManager.ROLE_GLOBAL_WALLETCHECK_ADMIN();
  const policyCreatorRole = await policyManager.ROLE_POLICY_CREATOR();
  const walletCheckAdminRole = await walletCheck.ROLE_WALLET_CHECK_ADMIN();
  const roleAggregator = await identityTree.ROLE_AGGREGATOR();
  const roleIdentityTreeAdmin = await credentialUpdater.ROLE_IDENTITY_TREE_ADMIN();

  const admin = signers.admin.address;
  const tx4 = await credentials.grantRole(credentialUpdaterRole, credentialUpdater.address);
  const tx5 = await policyManager.grantRole(issuerAdminRole, admin);
  const tx6 = await policyManager.grantRole(globalWalletCheckAdminRole, admin);
  const tx7 = await policyManager.grantRole(policyCreatorRole, admin);
  const tx8 = await walletCheck.grantRole(walletCheckAdminRole, admin);
  const tx9 = await identityTree.grantRole(roleAggregator, admin);
  const tx10 = await credentialUpdater.grantRole(roleIdentityTreeAdmin, admin);

  await tx4.wait();
  await tx5.wait();
  await tx6.wait();
  await tx7.wait();
  await tx8.wait();
  await tx9.wait();
  await tx10.wait();

  console.log("contract internal roles configuration confirmed");

  /* --------------------- Admit Attestor and WalletCheck --------------------- */
  const attestorAddress = "0xbF76cca6D678949E207D7fB66136bbFdd4E317aF";
  const tx11 = await policyManager.admitAttestor(attestorAddress, "bulut");
  const tx12 = await policyManager.admitWalletCheck(walletCheck.address);
  // NOTE granting an aggregator with the `ROLE_AGGREGATOR` on the IdentityTree contract is missing
  await tx11.wait();
  await tx12.wait();

  console.log("contract Attestor and Walletcheck configuration confirmed");

  /* ------------------------------ Deployer Info ------------------------------ */

  const deploymentInfo = {
    roles: {
      admin: signers.admin.address,
    },
    contracts: {
      IdentityConstructionProofVerifier: {
        address: identityConstructionProofVerifier.address,
        abi: IdentityConstructionProofVerifier.abi,
      },
      IdentityMembershipProofVerifier: {
        address: identityMembershipProofVerifier.address,
        abi: IdentityMembershipProofVerifier.abi,
      },
      AuthorizationProofVerifier: {
        address: authorizationProofVerifier.address,
        abi: AuthorizationProofVerifier.abi,
      },
      KeyringMinimalForwarder: {
        address: forwarder.address,
        abi: NoImplementation.abi,
      },
      KeyringZkVerifier: {
        address: keyringZkVerifier.address,
        abi: KeyringZkVerifier.abi,
      },
      KeyringCredentials: {
        address: credentials.address,
        abi: KeyringCredentials.abi,
      },
      RuleRegistry: {
        address: ruleRegistry.address,
        abi: RuleRegistry.abi,
      },
      PackLib: {
        address: packLib.address,
        abi: packLib.abi,
      },
      PolicyManager: {
        address: policyManager.address,
        abi: PolicyManager.abi,
      },
      UserPolicies: {
        address: userPolicies.address,
        abi: UserPolicies.abi,
      },
      PolicyStorage: {
        address: policyStorage.address,
        abi: policyStorage.abi,
      },
      KeyringZkCredentialUpdater: {
        address: credentialUpdater.address,
        abi: KeyringZkCredentialUpdater.abi,
      },
      WalletCheck: {
        address: walletCheck.address,
        abi: walletCheck.abi,
      },
      IdentityTree: {
        address: identityTree.address,
        abi: identityTree.abi,
      },
    },
  };

  if (!fs.existsSync(contractsDir)){
    fs.mkdirSync(contractsDir, { recursive: true });
  }
  fs.writeFileSync(`${contractsDir}/deployment.json`, JSON.stringify(deploymentInfo, undefined, 2));

  console.log("Admin has all roles:           ", signers.admin.address);
});
