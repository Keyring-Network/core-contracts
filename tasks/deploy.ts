import { task } from "hardhat/config";
import { TaskArguments } from "hardhat/types";
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/dist/src/signer-with-address";

const fs = require("fs");

const timestamp = Date.now();
const contractsDir = `${__dirname}/../deploymentInfo/${timestamp}`;

import IdentityConstructionProofVerifier from "../artifacts/contracts/zkVerifiers/identityContructionProof/contracts/IdentityConstructionProofVerifier.sol/Verifier.json";
import AuthorizationProofVerifier from "../artifacts/contracts/zkVerifiers/authorizationProof/contracts/AuthorizationProofVerifier.sol/Verifier.json";
import IdentityMembershipProofVerifier from "../artifacts/contracts/zkVerifiers/membershipProof/contracts/IdentityMembershipProofVerifier.sol/Verifier20.json";
import {
  IdentityTree__factory,
  PackLib__factory,
  WalletCheck__factory,
  NoImplementation__factory,
  KeyringCredentials__factory,
  RuleRegistry__factory,
  PolicyManager__factory,
  KeyringZkCredentialUpdater__factory,
  KeyringZkVerifier__factory,
  PolicyStorage__factory,
} from "../src/types";
import { genesis } from "../constants";
import { Contract } from "ethers";

export interface Signers {
  admin: SignerWithAddress;
}

// TODO: THIS IS DEPLOYING NON-UPGRADABLE CONTRACTS. REFACTOR FOR PROXY DEPLOYMENT.

task("deploy").setAction(async function (taskArguments: TaskArguments, { ethers }) {
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
  const PolicyStorage = await PolicyStorageFactory.deploy();
  const PolicyManagerFactory = await ethers.getContractFactory("PolicyManager", {
    libraries: {
      PolicyStorage: PolicyStorage.address,
    },
  });
  const policyManager = await PolicyManagerFactory.deploy(forwarder.address, ruleRegistry.address);
  console.log("PolicyManager:                 ", policyManager.address);

  /* --------------------------- KeyringCredentials --------------------------- */
  const CredentialFactory = await ethers.getContractFactory("KeyringCredentials");
  const credentials = await CredentialFactory.deploy(forwarder.address, policyManager.address);
  console.log("KeyringCredentials:            ", credentials.address);

  /* ---------------------- KeyringZkCredentialUpdater ----------------------- */
  const PackLib = await ethers.getContractFactory("PackLib");
  const packLib = await PackLib.deploy();
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
  const WalletCheck = await ethers.getContractFactory("WalletCheck");
  const walletCheck = await WalletCheck.deploy(forwarder.address);
  console.log("WalletCheck:                  ", walletCheck.address);

  /* ------------------------------ IdentityTree ------------------------------ */
  const IdentityTree = await ethers.getContractFactory("IdentityTree");
  const identityTree = await IdentityTree.deploy(forwarder.address);
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
  await credentialUpdater.deployed();
  await PolicyStorage.deployed();
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

  console.log("contract internal roles configuration confirmed");

  await tx4.wait();
  await tx5.wait();
  await tx6.wait();
  await tx7.wait();
  await tx8.wait();
  await tx9.wait();
  await tx10.wait();

  const deploymentInfo = {
    roles: {
      admin: signers.admin.address,
    },
    contracts: {
      KeyringMinimalForwarder: {
        address: forwarder.address,
        abi: NoImplementation__factory.abi,
      },
      KeyringZkVerifier: {
        address: keyringZkVerifier.address,
        abi: KeyringZkVerifier__factory.abi,
      },
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
      KeyringCredentials: {
        address: credentials.address,
        abi: KeyringCredentials__factory.abi,
      },
      RuleRegistry: {
        address: ruleRegistry.address,
        abi: RuleRegistry__factory.abi,
      },
      PackLib: {
        address: packLib.address,
        abi: PackLib__factory.abi,
      },
      PolicyManager: {
        address: policyManager.address,
        abi: PolicyManager__factory.abi,
      },
      PolicyStorage: {
        address: PolicyStorage.address,
        abi: PolicyStorage__factory.abi,
      },
      KeyringZkCredentialUpdater: {
        address: credentialUpdater.address,
        abi: KeyringZkCredentialUpdater__factory.abi,
      },
      WalletCheck: {
        address: walletCheck.address,
        abi: WalletCheck__factory.abi,
      },
      IdentityTree: {
        address: identityTree.address,
        abi: IdentityTree__factory.abi,
      },
    },
  };

  if (!fs.existsSync(contractsDir)) {
    fs.mkdirSync(contractsDir);
  }
  fs.writeFileSync(`${contractsDir}/deployment.json`, JSON.stringify(deploymentInfo, undefined, 2));

  console.log("Admin has all roles:           ", signers.admin.address);
});
