import { execSync } from "child_process";
import { BigNumber, ContractReceipt, ethers, Contract, ContractFactory } from "ethers";
import {
  ContractEvent,
  ContractInfo,
  ContractInit,
  ContractList,
  ContractRoles,
  ContractRolesWithDetails,
  DeploymentInfo,
  EventTopic,
  ProxyOptions,
  RoleOperation,
} from "./types";
import fs from "fs";
import path from "path";
import { promises as fsp } from "fs";
import { FactoryOptions, HardhatRuntimeEnvironment } from "hardhat/types";
import { ROLE_TO_ID } from "./roles";
import {
  DEFAULT_FILENAME,
  ALL_ROLE_CHANGING_EVENTS,
  SEPOLIA_ADMIN_ADDRESS,
  SEPOLIA_AGGREGATOR_ADDRESS,
  SEPOLIA_WALLET_CHECK,
  MAINNET_ADMIN_ADDRESS,
  MAINNET_AGGREGATOR_ADDRESS,
  MAINNET_WALLET_CHECK,
  ADMIN_SLOT,
  IMPLEMENTATION_SLOT,
  TRANSPARENT_PROXY_ADMIN_ABI,
} from "./constants";
import { HardhatEthersHelpers } from "@nomiclabs/hardhat-ethers/types";

/**
 * @param networkName Name of the network
 * @returns The admin and aggregator addresses for the given network
 */
export const getAddresses = (networkName: string) => {
  let ADMIN;
  let AGGREGATOR;
  let WALLET_CHECK;

  switch (networkName) {
    case "mainnet":
      ADMIN = MAINNET_ADMIN_ADDRESS;
      AGGREGATOR = MAINNET_AGGREGATOR_ADDRESS;
      WALLET_CHECK = MAINNET_WALLET_CHECK;
      break;
    case "sepolia":
      ADMIN = SEPOLIA_ADMIN_ADDRESS;
      AGGREGATOR = SEPOLIA_AGGREGATOR_ADDRESS;
      WALLET_CHECK = SEPOLIA_WALLET_CHECK;
      break;
    case "hardhat": // testing
      ADMIN = "0x1234567890123456789012345678901234567890";
      AGGREGATOR = "0x1234567890123456789012345678901234567891";
      WALLET_CHECK = "0x1234567890123456789012345678901234567892";
      break;
    case "localhost": // testing
      ADMIN = "0x1234567890123456789012345678901234567890";
      AGGREGATOR = "0x1234567890123456789012345678901234567891";
      WALLET_CHECK = "0x1234567890123456789012345678901234567892";
      break;
    default:
      throw new Error(`Unknown network ${networkName}`);
  }

  if (!ADMIN || !AGGREGATOR || !WALLET_CHECK) {
    throw new Error("ADMIN_ADDRESS or AGGREGATOR env variable not set");
  }

  return { ADMIN, AGGREGATOR, WALLET_CHECK };
};

/**
 * @param contractInits An array of contracts and their init arguments
 */
export const initAndConfirm = async (contractInits: ContractInit[]) => {
  for (const { contract, args = [] } of contractInits) {
    const tx = await contract.init(...args);
    await tx.wait();
  }
};

/**
 * Writes the deployment info to a file
 * @param data The data to write to the file
 * @param dir The directory to write the file to, if not provided, the latest deployment directory will be used
 * @param fileName The name of the file to write to, if not provided, the default name will be used
 * @param networkName The name of the network, required if dir is not provided
 */
export const writeDeploymentInfoToFile = (data: any, dir?: string, fileName?: string, networkName?: string) => {
  let filePath;
  const _fileName = fileName ?? DEFAULT_FILENAME;
  if (dir) {
    filePath = path.join(dir, _fileName);
  } else {
    if (!networkName) throw new Error("networkName is required");
    filePath = path.join(getLatestDeploymentDir(networkName), _fileName);
  }

  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(filePath, JSON.stringify(data, undefined, 2));

  console.log(`Wrote file ${filePath} successfully.`);
};

export const getLatestDeploymentDir = (networkName: string) => {
  const contractsDir = __dirname + "/../deploymentInfo/" + networkName;
  const result = fs.readdirSync(contractsDir).sort().reverse();
  const subdir = result[0];
  return contractsDir + "/" + subdir;
};

export const getDeploymentDir = (networkName: string, deploymentId: string) => {
  const contractsDir = __dirname + "/../deploymentInfo/" + networkName;
  return contractsDir + "/" + deploymentId;
};

/**
 * @returns Returns deployment info from the latest deployment based on the timestamp
 */
export const getDeploymentInfo = async (networkName: string, fileName = DEFAULT_FILENAME, dir?: string): Promise<DeploymentInfo> => {
  const deploymentDir = dir || getLatestDeploymentDir(networkName);
  console.log("Reading DeploymentInfo from: " + deploymentDir + "/" + fileName);
  const deploymentInfo = await fsp.readFile(deploymentDir + "/" + fileName);
  return JSON.parse(deploymentInfo.toString());
};

/**
 * @param ruleIds The ruleIds to sort
 * @returns Returns the ruleIds in ascending order which is required for expression rules
 */
export const sortAscendingOrder = (ruleIds: string[]) => {
  return ruleIds.sort();
};

export const executeRoleTransactions = async (
  hre: HardhatRuntimeEnvironment,
  ownerAddress: string,
  roles: ContractRoles,
  operation: RoleOperation,
  gasPrice?: BigNumber,
): Promise<{ transactions: ContractReceipt[]; roleDetails: ContractRolesWithDetails }> => {
  const transactions = [];
  const roleDetails: ContractRolesWithDetails = {};

  const deploymentInfo = await getDeploymentInfo(hre.network.name);

  for (const contractName in roles) {
    const contractAddress = deploymentInfo.contracts[contractName].address;
    const contract = await getContract(hre, contractName, contractAddress);
    const rolesForContract = roles[contractName];

    console.log("\n");
    console.log(`▶️ ${contractName}:`);

    for (const roleName of rolesForContract) {
      const roleId = getRoleID(roleName);
      console.log(
        `${operation === RoleOperation.Grant ? "GRANT" : "RENOUNCE"} ${roleName} (ID: ${roleId}) ${
          operation === RoleOperation.Grant ? "to" : "from"
        } ${ownerAddress}`,
      );

      const tx = await contract[operation](roleId, ownerAddress, { gasPrice });
      transactions.push(await tx.wait());

      if (!roleDetails[contractName]) {
        roleDetails[contractName] = [];
      }
      roleDetails[contractName].push({ name: roleName, id: roleId });
    }
  }

  return { transactions, roleDetails };
};

export const hasRole = async (
  hre: HardhatRuntimeEnvironment,
  contractName: string,
  contractAddress: string,
  roleName: string,
  address: string,
) => {
  const contract = await getContract(hre, contractName, contractAddress);
  const roleId = getRoleID(roleName);
  return await contract.hasRole(roleId, address);
};

export const getContract = async (hre: HardhatRuntimeEnvironment, contractName: string, contractAddress: string) => {
  return await hre.ethers.getContractAt(contractName, contractAddress);
};

export const getRoleID = (role: string): string => {
  const roleID = ROLE_TO_ID[role];
  if (!roleID) {
    throw new Error(`Role ${role} not found`);
  }
  return roleID;
};

export const getPolicyAdminRoleID = (policyId: number): string => {
  const policyIdBn = ethers.BigNumber.from(policyId);
  const policyIdBytes32 = ethers.utils.hexZeroPad(policyIdBn.toHexString(), 32);
  return policyIdBytes32;
};

export function getPolicyUserAdminRoleId(policyId: number) {
  const packed = ethers.utils.solidityPack(["uint32", "bytes32"], [policyId, ROLE_TO_ID.SEED_POLICY_OWNER]);
  return ethers.utils.keccak256(packed);
}

export const log = (msg: string) => {
  console.log("");
  console.log(`🔹🔹🔹🔹🔹🔹🔹🔹 ${msg} 🔹🔹🔹🔹🔹🔹🔹🔹`);
  console.log("");
};

export async function deployContract<Factory extends ContractFactory, ContractType extends Contract>(
  contractName: string,
  constructorArgs: any[],
  hre: HardhatRuntimeEnvironment,
  useProxy?: boolean,
  proxyOptions?: ProxyOptions,
  factoryOptions?: FactoryOptions,
): Promise<{ contract: ContractType; factory: Factory }> {
  const factory = (await hre.ethers.getContractFactory(contractName, factoryOptions)) as Factory;

  let _proxyOptions = {};
  if (useProxy) {
    _proxyOptions = {
      ...proxyOptions,
      kind: proxyOptions?.kind || "transparent",
      unsafeAllow: proxyOptions?.unsafeAllow || [],
      constructorArgs: constructorArgs,
    };
  }

  let contract;

  const [DEPLOYER] = await hre.ethers.getSigners();
  const currentNonce = await getCurrentNonce(hre, DEPLOYER.address);
  console.log(`Start deploying contract ${contractName} with nonce ${currentNonce}`);

  if (useProxy) {
    contract = (await hre.upgrades.deployProxy(factory, _proxyOptions)) as ContractType;
  } else {
    contract = (await factory.deploy(...constructorArgs)) as ContractType;
  }

  console.log(`Contract ${contractName} address:`, contract.address);
  const txHash = contract.deployTransaction.hash;
  console.log("Transaction hash:", txHash);

  // set intervall until tx is mined and contract is deployed, console log status every 5 seconds
  const intervall = setInterval(async () => {
    const receipt = await hre.ethers.provider.getTransactionReceipt(txHash);
    if (receipt) {
      console.log("Transaction mined!");
      clearInterval(intervall);
    } else {
      console.log("Waiting for transaction to be mined...");
    }
  }, 5000);

  await contract.deployed();

  return { contract, factory };
}

export function getContractByName(contractName: string, contracts: ContractList[]): Contract {
  const foundContract = contracts.find(contract => contract.name === contractName);
  if (!foundContract) throw new Error("Could not find contract");
  return foundContract.contract;
}

export const getRoleName = (id: string): string => {
  const keys = Object.keys(ROLE_TO_ID);
  const values = Object.values(ROLE_TO_ID);
  const foundIndex = values.findIndex(value => value === id);
  return keys[foundIndex];
};

export const getEventLogs = async (
  events: EventTopic[],
  contracts: ethers.Contract[],
  contractInfo: ContractInfo[],
  startBlock: number,
  endBlock: number,
  hre: HardhatRuntimeEnvironment,
) => {
  const allEventLogs: ContractEvent[] = [];

  for (const event of events) {
    console.log(`...getting past ${event.name} events`);

    for (const contract of contracts) {
      const filter = {
        address: contract.address,
        fromBlock: startBlock,
        toBlock: endBlock,
        topics: [event.topic],
      };

      const logs = await hre.waffle.provider.getLogs(filter);
      const _events = logs.map(log => {
        return {
          ...contract.interface.parseLog(log),
          blockNumber: log.blockNumber,
          contract: contractInfo.find(info => info.address === contract.address)?.name as string,
          type: event.name,
        };
      });

      allEventLogs.push(..._events);
    }
  }

  return allEventLogs;
};

/**
 *
 * @param abi Contract ABI
 * @returns all events and topics from a single contract interface
 *
 */
export const getEventTopics = (abi: string) => {
  return ALL_ROLE_CHANGING_EVENTS.map(eventName => {
    const _interface = new ethers.utils.Interface(abi);
    const event = _interface.getEvent(eventName);
    const topic = _interface.getEventTopic(event);

    return {
      name: eventName,
      topic: topic,
    };
  });
};

export const getCurrentCommitHash = () => {
  try {
    const commitHash = execSync("git rev-parse HEAD").toString().trim();
    return commitHash;
  } catch (err) {
    console.error("Error reading git commit hash:", err);
    return;
  }
};

async function getCurrentNonce(hre: HardhatRuntimeEnvironment, address: string) {
  const provider = hre.ethers.provider;
  const nonce = await provider.getTransactionCount(address);
  return nonce;
}

const bytes32ToHexAddress = (hex: string) => "0x" + hex.slice(26);

/**
 * Upgrades a contract using a proxy admin contract (TransparentUpgradeableProxy)
 * @param _ethers - ethers object from hardhat with provider
 * @param contractName - name of the contract to upgrade
 * @param proxyAddress - address of the proxy contract for the contract to upgrade
 * @param constructorArgs - constructor arguments for the new implementation contract
 * @param libraries - addresses of libraries to link to the new implementation contract
 * @returns - address of the new implementation contract
 */
export const upgradeContract = async (
  _ethers: HardhatEthersHelpers,
  contractName: string,
  proxyAddress: string,
  constructorArgs: any[] = [],
  libraries: string[] = [],
): Promise<string> => {
  if (proxyAddress === ethers.constants.AddressZero) {
    throw new Error("Proxy address is zero.");
  }

  console.log("Upgrading contract:", contractName);
  console.log("Proxy address:", proxyAddress);

  const proxyAdminAddress = bytes32ToHexAddress(await _ethers.provider.getStorageAt(proxyAddress, ADMIN_SLOT));
  const proxyAdmin = await _ethers.getContractAt(TRANSPARENT_PROXY_ADMIN_ABI, proxyAdminAddress);

  // Ensure that the proxy admin address is not zero
  if (proxyAdminAddress === ethers.constants.AddressZero) {
    throw new Error("Proxy admin address is zero. Please check if the proxy is deployed correctly.");
  }

  // Ensure that the signer is the owner of the proxy admin or the upgrade might fail
  const proxyAdminOwner = await proxyAdmin.owner();
  const signerAddress = await _ethers.provider.getSigner().getAddress();
  if (proxyAdminOwner.toLowerCase() !== signerAddress.toLowerCase()) {
    throw new Error(`Signer is not the owner. Proxy admin owner is ${proxyAdminOwner}.`);
  }

  console.log("Proxy admin contract address:", proxyAdminAddress);

  // Sanity checks to ensure that the proxy is deployed correctly
  const currentImplementation = bytes32ToHexAddress(
    await _ethers.provider.getStorageAt(proxyAddress, IMPLEMENTATION_SLOT),
  );
  if (currentImplementation === ethers.constants.AddressZero) {
    throw new Error("Current implementation address is zero. Please check if the proxy is deployed correctly.");
  }
  console.log("Current implementation address:", currentImplementation);

  const proxyImplementationFromProxyAdmin = await proxyAdmin.getProxyImplementation(proxyAddress);
  if (proxyImplementationFromProxyAdmin.toLowerCase() !== currentImplementation.toLowerCase()) {
    throw new Error(
      `Current implementation address from proxy admin is ${proxyImplementationFromProxyAdmin}. Proxy admin is not corrrect.`,
    );
  }

  const proxyAdminFromProxyAdmin = await proxyAdmin.getProxyAdmin(proxyAddress);
  if (proxyAdminFromProxyAdmin.toLowerCase() !== proxyAdminAddress.toLowerCase()) {
    throw new Error(
      `Proxy admin address from proxy admin is ${proxyAdminFromProxyAdmin}. Proxy admin is not corrrect.`,
    );
  }

  // Prepare libraries
  const libraryAddresses: any = {};
  for (let i = 0; i < libraries.length; i++) {
    const libraryFactory = await _ethers.getContractFactory(libraries[i]);
    libraryAddresses[libraries[i]] = (await libraryFactory.deploy()).address;
  }

  if (libraries.length > 0) console.log("Libraries:", libraryAddresses);
  if (constructorArgs.length > 0) console.log("Constructor args:", constructorArgs);

  // Deploy new implementation contract
  const newImplementationFactory = await _ethers.getContractFactory(contractName, { libraries: libraryAddresses });
  const newImplementationAddress = (await newImplementationFactory.deploy(...constructorArgs)).address;
  console.log("New implementation address:", newImplementationAddress);

  // Perform contract upgrade
  await proxyAdmin.upgrade(proxyAddress, newImplementationAddress);

  const newOnChainImplementation = bytes32ToHexAddress(
    await _ethers.provider.getStorageAt(proxyAddress, IMPLEMENTATION_SLOT),
  );
  if (newOnChainImplementation.toLowerCase() !== newImplementationAddress.toLowerCase()) {
    throw new Error(
      `Upgrade failed.\nExpected implementation: ${newImplementationAddress}.\nActual implementation: ${newOnChainImplementation}`,
    );
  }

  return newImplementationAddress;
};
