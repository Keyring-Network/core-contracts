import { task, types } from "hardhat/config";
import {
  deployContract,
  getAddresses,
  getContractByName,
  getCurrentCommitHash,
  getDeploymentInfo,
  log,
  writeDeploymentInfoToFile,
  getDeploymentDir,
} from "../deploy/helpers";
import { DEFAULT_FILENAME } from "../deploy/constants";
import { ContractList, DeploymentInfo } from "../deploy/types";
import { KeyringCredentials } from "../src/types";

interface ContractAddresses {
  forwarder: string;
  keyringCredentials: string;
  policyManager: string;
}

// example: npx hardhat deploy-merkle-auth --deployment-id 1700837879040  --network sepolia
task("deploy-merkle-auth", "Deploy Merkle Auth contracts")
  .addParam("deploymentId", "ID of the existing deployment to use as base", "", types.string)
  .setAction(async (taskArgs, hre) => {
    const { ethers, network } = hre;
    const { deploymentId } = taskArgs;
    console.log({ deploymentId });

    const { ADMIN } = getAddresses(network.name);

    const contracts: ContractList[] = [];

    const deploymentDir = getDeploymentDir(network.name, deploymentId);
    const deploymentInfo = await getDeploymentInfo(network.name, DEFAULT_FILENAME, deploymentDir);

    const addresses: ContractAddresses = {
      forwarder: deploymentInfo.contracts.KeyringMinimalForwarder.address,
      keyringCredentials: deploymentInfo.contracts.KeyringCredentials.address,
      policyManager: deploymentInfo.contracts.PolicyManager.address,
    };

    const timestamp = Date.now();
    const blockNumber = await ethers.provider.getBlockNumber();
    const commitHash = getCurrentCommitHash();
    console.log(`DEPLOYMENT HAS STARTED (timestamp: ${timestamp}, block: ${blockNumber})`);
    console.log("Current commit hash:", commitHash);

    /* ---------------------------- KeyringMerkleAuthZkVerifier --------------------------- */
    let name = "MerkleAuthVerifier";
    {
      const { contract, factory } = await deployContract(name, [], hre);
      contracts.push({ name, contract, factory });
    }
    const merkleAuthVerifierAddress = getContractByName(name, contracts)?.address;

    name = "KeyringMerkleAuthZkVerifier";
    {
      const constructorArgs = [merkleAuthVerifierAddress];
      const { contract, factory } = await deployContract(name, constructorArgs, hre);
      contracts.push({ name, contract, factory, constructorArgs });
    }
    const keyringMerkleAuthZkVerifierAddress = getContractByName(name, contracts)?.address;

    /* ---------------------- KeyringZkCredentialUpdater ----------------------- */
    name = "KeyringMerkleAuthZkCredentialUpdater";
    {
      const constructorArgs = [
        addresses.forwarder,
        addresses.keyringCredentials,
        addresses.policyManager,
        keyringMerkleAuthZkVerifierAddress,
      ];
      const { contract, factory } = await deployContract(name, constructorArgs, hre);
      contracts.push({ name, contract, factory, constructorArgs });
    }
    const keyringMerkleAuthZkCredentialUpdaterAddress = getContractByName(name, contracts)?.address;

    /* ---------------------- Grant KeyringZkCredentialUpdater ----------------------- */
    const credentials = (await ethers.getContractAt(
      "KeyringCredentials",
      deploymentInfo.contracts.KeyringCredentials.address,
    )) as KeyringCredentials;
    
    const ROLE_CREDENTIAL_UPDATER = await credentials.ROLE_CREDENTIAL_UPDATER();

    let hasRole = await credentials.hasRole(ROLE_CREDENTIAL_UPDATER, keyringMerkleAuthZkCredentialUpdaterAddress);

    console.log(keyringMerkleAuthZkCredentialUpdaterAddress, hasRole);

    if (hasRole) {
      console.log("updater already has role.");
    } else {
      console.log("updater does not have role. Granting...");
      // NOTE: uncomment to grant role
      // const tx = await credentials.grantRole(ROLE_CREDENTIAL_UPDATER, keyringMerkleAuthZkCredentialUpdaterAddress);
      // console.log("tx", tx.hash);
      // tx.wait();
      // hasRole = await credentials.hasRole(ROLE_CREDENTIAL_UPDATER, keyringMerkleAuthZkCredentialUpdaterAddress);
      // console.log(keyringMerkleAuthZkCredentialUpdaterAddress, hasRole);
    }

    /* ---------------------------------- DONE ---------------------------------- */

    log("MERKLE AUTH CONTRACTS DEPLOYED");

    const deployementInfoMerkleAuth: DeploymentInfo = {
      blockNumber: blockNumber,
      commitHash: commitHash,
      roles: [
        {
          name: "Default Admin",
          address: "",
          granted: {},
        },
      ],
      contracts: {},
    };

    for (const { name, contract, factory, constructorArgs } of contracts) {
      deployementInfoMerkleAuth.contracts[name] = {
        address: contract.address,
        abi: JSON.parse(factory.interface.format("json") as string),
        constructorArgs: constructorArgs || [],
        isProxy: false,
      };
    }

    writeDeploymentInfoToFile(deployementInfoMerkleAuth, deploymentDir, `deployment-merkle-auth.json`, network.name);
  });
