import { task } from "hardhat/config";
import * as fs from "fs";
import * as path from "path";

import {
  WALLETCHECK_URI,
  ozNetworkToFilename,
  MAXIMUM_CONSENT_PERIOD,
  GENESIS_RULE_REGISTRY,
} from "../deploy/constants";
import { deployContract, getContractByName, getCurrentCommitHash, initAndConfirm, writeDeploymentInfoToFile } from "../deploy/helpers";
import { ContractList, DeploymentInfo } from "../deploy/types";

/**
 * Deploys the core contracts and writes the deployment info to a file.
 * Upgradability is enabled for specific contracts (see `upgrades.deployProxy`).
 * @example npx hardhat deploy
 */
task("deploy", "Deploys the core contracts").setAction(async function (_, hre) {
  const { ethers, upgrades, network } = hre;

  // silence hardhat-upgrades warnings for unsafeAllow flags
  upgrades.silenceWarnings();

  const [DEPLOYER] = await ethers.getSigners();

  const contracts: ContractList[] = [];

  const timestamp = Date.now();
  const blockNumber = await ethers.provider.getBlockNumber();
  const commitHash = getCurrentCommitHash();
  console.log(`DEPLOYMENT HAS STARTED (timestamp: ${timestamp}, block: ${blockNumber})`);
  console.log(`Deploying contracts on ${network.name}...`);
  console.log("Deployer account:", DEPLOYER.address);
  console.log("Current commit hash:", commitHash);

  /* --------------------------------- Proxies -------------------------------- */
  // NOTE: when calling `upgrades.deployProxy` for the first time and without pre-existing proxies,
  // the proxy admin contract will be deployed first and linked to the proxy.
  // Afterwards the implementation contract will be deployed and linked to the proxy.
  // Check `.openzeppelin/` folder for more details.
  console.log("Deploying proxies...");

  const useProxy = true;

  /* ------------------------------ Forwarder ------------------------------ */
  let name = "KeyringMinimalForwarder"; // NOTE - contract name was renamed to `NoImplementation`
  {
    const { contract, factory } = await deployContract("NoImplementation", [], hre, useProxy);
    contracts.push({ name, contract, factory, isProxy: useProxy });
  }
  const forwarderAddress = getContractByName(name, contracts)?.address;

  /* ---------------------------- KeyringZkVerifier --------------------------- */
  name = "ConstructionVerifier";
  {
    const { contract, factory } = await deployContract(name, [], hre);
    contracts.push({ name, contract, factory });
  }
  const constructionVerifierAddress = getContractByName(name, contracts)?.address;

  name = "MembershipVerifier20";
  {
    const { contract, factory } = await deployContract(name, [], hre);
    contracts.push({ name, contract, factory });
  }
  const MembershipVerifierAddress = getContractByName(name, contracts)?.address;

  name = "AuthorizationVerifier";
  {
    const { contract, factory } = await deployContract(name, [], hre);
    contracts.push({ name, contract, factory });
  }
  const authorizationVerifierAddress = getContractByName(name, contracts)?.address;

  name = "KeyringZkVerifier";
  {
    const constructorArgs = [constructionVerifierAddress, MembershipVerifierAddress, authorizationVerifierAddress];
    const { contract, factory } = await deployContract(name, constructorArgs, hre);
    contracts.push({ name, contract, factory, constructorArgs });
  }
  const keyringZkVerifierAddress = getContractByName(name, contracts)?.address;

  /* ------------------------------ RuleRegistry ------------------------------ */

  name = "RuleRegistry";
  {
    const constructorArgs = [forwarderAddress];
    const { contract, factory } = await deployContract(name, constructorArgs, hre, useProxy, {
      unsafeAllow: ["constructor", "delegatecall"],
    });
    contracts.push({ name, contract, factory, constructorArgs, isProxy: useProxy });
  }
  const ruleRegistryAddress = getContractByName(name, contracts)?.address;

  /* ------------------------------ PolicyManager ------------------------------ */
  name = "PolicyStorage";
  {
    const { contract, factory } = await deployContract(name, [], hre);
    contracts.push({ name, contract, factory });
  }
  const policyStorageAddress = getContractByName(name, contracts)?.address;

  name = "PolicyManager";
  {
    const constructorArgs = [forwarderAddress, ruleRegistryAddress];
    const libraries = { PolicyStorage: policyStorageAddress as string };
    const { contract, factory } = await deployContract(
      name,
      constructorArgs,
      hre,
      useProxy,
      {
        unsafeAllow: ["constructor", "delegatecall", "external-library-linking"],
      },
      {
        libraries,
      },
    );
    contracts.push({ name, contract, factory, constructorArgs, isProxy: useProxy, libraries });
  }
  const policyManagerAddress = getContractByName(name, contracts)?.address;

  /* ------------------------------ UserPolicies ------------------------------ */
  name = "UserPolicies";
  {
    const constructorArgs = [forwarderAddress, policyManagerAddress];
    const { contract, factory } = await deployContract(name, constructorArgs, hre, useProxy, {
      unsafeAllow: ["constructor"],
    });
    contracts.push({ name, contract, factory, constructorArgs, isProxy: useProxy });
  }

  /* --------------------------- KeyringCredentials --------------------------- */
  name = "KeyringCredentials";
  {
    const constructorArgs = [forwarderAddress, policyManagerAddress, MAXIMUM_CONSENT_PERIOD];
    const { contract, factory } = await deployContract(name, constructorArgs, hre, useProxy, {
      unsafeAllow: ["constructor", "delegatecall", "state-variable-immutable"],
    });
    contracts.push({ name, contract, factory, constructorArgs, isProxy: useProxy });
  }
  const keyringCredentialsAddress = getContractByName(name, contracts)?.address;

  /* ---------------------- KeyringZkCredentialUpdater ----------------------- */
  name = "KeyringZkCredentialUpdater";
  {
    const constructorArgs = [
      forwarderAddress,
      keyringCredentialsAddress,
      policyManagerAddress,
      keyringZkVerifierAddress,
    ];
    const { contract, factory } = await deployContract(name, constructorArgs, hre);
    contracts.push({ name, contract, factory, constructorArgs });
  }

  /* --------------------------- ExemptionsManager ---------------------------- */
  name = "ExemptionsManager";
  {
    const constructorArgs = [forwarderAddress];
    const { contract, factory } = await deployContract(name, constructorArgs, hre, useProxy, {
      unsafeAllow: ["constructor", "delegatecall"],
    });
    contracts.push({ name, contract, factory, constructorArgs, isProxy: useProxy });
  }

  /* ------------------------------- WalletCheck ------------------------------ */
  name = "WalletCheck";
  {
    const constructorArgs = [forwarderAddress, policyManagerAddress, MAXIMUM_CONSENT_PERIOD, WALLETCHECK_URI];
    const { contract, factory } = await deployContract(name, constructorArgs, hre);
    contracts.push({ name, contract, factory, constructorArgs });
  }

  /* ------------------------------ IdentityTree ------------------------------ */
  name = "IdentityTree";
  {
    const constructorArgs = [forwarderAddress, policyManagerAddress, MAXIMUM_CONSENT_PERIOD];
    const { contract, factory } = await deployContract(name, constructorArgs, hre);
    contracts.push({ name, contract, factory, constructorArgs });
  }

  /* ------------------ Wait for all contracts to be deployed ----------------- */
  for (const contract of contracts) {
    await contract.contract.deployed();
  }

  console.log("contract deployments confirmed");

  /* -------------------------- Initialize contracts -------------------------- */
  console.log("Initializing contracts...");

  await initAndConfirm([
    {
      contract: getContractByName("RuleRegistry", contracts),
      args: [...Object.values(GENESIS_RULE_REGISTRY)],
    },
    {
      contract: getContractByName("KeyringCredentials", contracts),
    },
    {
      contract: getContractByName("PolicyManager", contracts),
    },
    {
      contract: getContractByName("ExemptionsManager", contracts),
      args: [policyManagerAddress],
    },
  ]);

  console.log("contract initialization confirmed");

  /* -------------------------- Save deployment info -------------------------- */
  console.log("Saving deployment info...");

  const deploymentInfo: DeploymentInfo = {
    blockNumber: blockNumber,
    commitHash: commitHash,
    roles: [
      {
        name: "Deployer",
        address: "",
        granted: {},
      },
      {
        name: "Default Admin",
        address: "",
        granted: {},
      },
    ],
    contracts: {},
    upgradable: {},
  };

  deploymentInfo.roles[0].address = DEPLOYER.address; // DEPLOYER
  // NOTE - `Default Admin` role gets transferred via the separate `owner` task
  deploymentInfo.roles[1].address = DEPLOYER.address; // DEFAULT ADMIN

  for (const { name, contract, factory, constructorArgs, isProxy, libraries } of contracts) {
    deploymentInfo.contracts[name] = {
      address: contract.address,
      abi: JSON.parse(factory.interface.format("json") as string),
      constructorArgs: constructorArgs || [],
      libraries: libraries || undefined,
      isProxy: isProxy || false,
      implementationAddress: isProxy
        ? await (await upgrades.admin.getInstance()).getProxyImplementation(contract.address)
        : undefined,
    };
  }

  // Add OpenZeppelin upgradable info
  let openzeppelinData;
  try {
    const openzeppelinFile = path.join(__dirname, `../.openzeppelin/${ozNetworkToFilename[network.name]}.json`);
    openzeppelinData = JSON.parse(fs.readFileSync(openzeppelinFile, "utf8"));
  } catch (err) {
    console.error(`Failed to read or parse OpenZeppelin upgradable info: ${err}`);
    openzeppelinData = {}; // fallback to an empty object
  }
  deploymentInfo.upgradable = openzeppelinData;

  const contractsDir = `${__dirname}/../deploymentInfo/${network.name}/${timestamp}`;
  writeDeploymentInfoToFile(deploymentInfo, contractsDir);

  console.log("Deployment info saved");
  console.log("DEPLOYMENT HAS BEEN COMPLETED");
});
