import { task, types } from "hardhat/config";
import {
  getDeploymentInfo,
  getEventLogs,
  getEventTopics,
  getLatestDeploymentDir,
  getRoleName,
} from "../deploy/helpers";
import { ALL_CONTRACT_NAMES } from "../deploy/constants";
import { ethers } from "ethers";
import fs from "fs";
import { join } from "path";
import { ContractEvent, ContractInfo, RoleOwners, Snapshot } from "../deploy/types";

/**
 * Checks role owners and their given roles for all Contracts.
 * Writes data along with the history of assignment to a file in the tasks directory.
 * @param startBlock The block number to start from (optional) - defaults to the block number in the deployment info
 * @example npx hardhat roleOwners --network goerli
 * NOTE: Topics and events seems to be the saem accross all contracts. So we can just get all topics and events from one contract.
 */

task("roleOwners", "Check which roles are assigned to role owners")
  .addOptionalParam("startBlock", "The block number to start from", "", types.string)
  .setAction(async (taskArgs, hre) => {
    const networkName = hre.network.name;

    // Proxy admin
    const proxyAdmin = await hre.upgrades.admin.getInstance();
    const proxyAdminOwner = await proxyAdmin.owner();

    // retrieve most recent deployment info based on network
    const deploymentInfo = await getDeploymentInfo(networkName);

    const contractsInfo: ContractInfo[] = ALL_CONTRACT_NAMES.map(name => ({
      name,
      address: deploymentInfo.contracts[name].address,
      abi: deploymentInfo.contracts[name].abi,
    }));

    const contracts: ethers.Contract[] = await Promise.all(
      contractsInfo.map(info => hre.ethers.getContractAt(info.name, info.address)),
    );

    const startBlock = taskArgs.startBlock ? Number(taskArgs.startBlock) : Number(deploymentInfo.blockNumber);
    if (!startBlock) throw new Error("No start block provided and no block number found in deployment info.");

    const endBlock = await hre.ethers.provider.getBlockNumber();
    console.log(`Getting role owners and their roles from block ${startBlock} to ${endBlock} on ${networkName}`);

    const snapshot = {
      timestamp: Date.now(),
      startBlock: startBlock,
      endBlock: endBlock,
    };

    const handleRoleGrantedEvent = (
      roleOwners: Map<string, Set<RoleOwners>>,
      event: ContractEvent,
      historyObj: Record<string, string[]>,
    ) => {
      const { args, contract, blockNumber } = event;
      const { role: roleId, account } = args;
      const role = getRoleName(roleId);
      const history = historyObj[account] || [];
      const owner = roleOwners.get(account) || new Set<RoleOwners>();

      let roleObj = [...owner].find(obj => obj.contract === contract);

      if (!roleObj) {
        roleObj = {
          contract,
          roles: new Set<string>([role]),
        };
        owner.add(roleObj);
      } else if (!roleObj.roles.has(role)) {
        roleObj.roles.add(role);
      }

      history.push(`${role} GRANTED to ${account} in ${contract} contract. Block number - ${blockNumber}`);
      historyObj[account] = history;

      roleOwners.set(account, owner);
    };

    const handleRoleRevokedEvent = (
      roleOwners: Map<string, Set<RoleOwners>>,
      event: ContractEvent,
      historyObj: Record<string, string[]>,
    ) => {
      const { args, contract, blockNumber } = event;
      const { role: roleId, account } = args;
      const role = getRoleName(roleId);
      const history = historyObj[account] || [];
      const owner = roleOwners.get(account) || new Set<RoleOwners>();

      const roleObj = [...owner].find(obj => obj.contract === contract);

      if (roleObj && roleObj.roles.has(role)) {
        roleObj.roles.delete(role);
        history.push(`${role} REVOKED from ${account} in ${contract} contract. Block number - ${blockNumber}`);
        if (roleObj.roles.size === 0) owner.delete(roleObj);
      } else {
        console.error(
          `Role ${role} was not granted to ${account} in ${contract} contract. Block number - ${blockNumber}`,
          "Check if the role was granted before the start block.",
        );
      }

      historyObj[account] = history;
      owner.size > 0 ? roleOwners.set(account, owner) : roleOwners.delete(account);
    };

    const parseEventLogs = async () => {
      console.log("...parsing event logs");
      const roleOwners = new Map<string, Set<RoleOwners>>();
      const historyObj: Record<string, string[]> = {};
      const proxyAdmins: Set<string> = new Set();

      const eventTopics = getEventTopics(contractsInfo[0].abi);
      const logs = await getEventLogs(eventTopics, contracts, contractsInfo, startBlock, endBlock, hre);

      console.log("...sorting event logs");
      const sortedEventLogs = logs.sort((a, b) => a.blockNumber - b.blockNumber);

      console.log("...creating role owners map");
      for (const event of sortedEventLogs) {
        const { args, type } = event;
        const { account } = args as unknown as { role: string; account: string };
        const isProxyAdmin = account.toLowerCase() === proxyAdminOwner.toLowerCase();

        if (type === "RoleGranted") {
          handleRoleGrantedEvent(roleOwners, event, historyObj);
        } else {
          handleRoleRevokedEvent(roleOwners, event, historyObj);
        }

        if (!proxyAdmins.has(account) && isProxyAdmin) {
          proxyAdmins.add(account);
        }
      }

      return { roleOwners, history: historyObj, proxyAdmins };
    };

    const writeToFile = async (
      snapshot: Snapshot,
      proxyAdmins: Set<string>,
      roleOwners: Map<string, Set<RoleOwners>>,
      history: Record<string, string[]>,
    ) => {
      const json = JSON.stringify(
        { snapshot, proxyAdmins, roleOwners, history },
        (_, value) => {
          if (value instanceof Set) return [...value]; // convert Set to Array
          if (value instanceof Map) return Object.fromEntries(value.entries()); // convert Map to Object
          return value;
        },
        2,
      );

      console.log("...writing role owners and history to file");
      const deploymentDir = getLatestDeploymentDir(networkName);
      const path = join(deploymentDir, `roleOwners-${snapshot.timestamp}.json`);
      fs.writeFileSync(path, json);
    };

    const { roleOwners, history, proxyAdmins } = await parseEventLogs();

    await writeToFile(snapshot, proxyAdmins, roleOwners, history);

    console.log("...success!");
  });
