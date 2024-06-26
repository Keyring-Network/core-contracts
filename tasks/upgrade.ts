import { task } from "hardhat/config";
import { getCurrentCommitHash, getDeploymentInfo, writeDeploymentInfoToFile, upgradeContract } from "../deploy/helpers";
import { UpgradeInfo } from "../deploy/types";

/**
 * @notice Upgrades a contract and writes the new implementation address to the deployment info file.
 * @param contract - address of the proxy contract for the contract to upgrade
 * @param args - constructor arguments for the new implementation contract
 * @param libraries - names of libraries to link with new implementation contract
 * @param proxyName - Proxy Name in the deployment info file, defaults to the contract name
 *
 * @example npx hardhat upgrade --network goerli --contract RuleRegistry --args '["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]'
 */
task("upgrade", "Upgrade Contract")
  .addParam("contract", "Name of contract to upgrade")
  .addOptionalParam("args", "Constructor arguments for ", "[]")
  .addOptionalParam("libraries", "Names of libraries to link with new implementation contract", "[]")
  .addOptionalParam("proxyName", "Proxy Name in the deployment info file", "")
  .setAction(async (taskArgs, hre) => {
    const { ethers, network } = hre;
    const { contract, args, libraries, proxyName } = taskArgs;

    const deploymentInfo = await getDeploymentInfo(network.name);
    const contractName = proxyName || contract; // forwarder proxy is named KeyringMinimalForwarder, but the contract is named NoImplementation
    const proxyAddress = deploymentInfo.contracts[contractName].address;

    const timestamp = Date.now();
    const blockNumber = await ethers.provider.getBlockNumber();
    const commitHash = getCurrentCommitHash();
    console.log(`DEPLOYMENT HAS STARTED (timestamp: ${timestamp}, block: ${blockNumber})`);
    console.log("Current commit hash:", commitHash);

    const newImplementationAddress = await upgradeContract(
      ethers,
      contract,
      proxyAddress,
      JSON.parse(args),
      JSON.parse(libraries),
    );

    /* ---------------------------------- DONE ---------------------------------- */

    const upgradeInfo: UpgradeInfo = {
      name: contract,
      address: proxyAddress,
      newImplementationAddress: newImplementationAddress,
      blockNumber: blockNumber,
      commitHash: commitHash,
    };

    writeDeploymentInfoToFile(upgradeInfo, undefined, `contract-upgrade-${upgradeInfo.name}.json`, network.name);
  });
