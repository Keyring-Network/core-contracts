import { task, types } from "hardhat/config";
import { getDeploymentInfo } from "../deploy/helpers";
import { DEFAULT_FILENAME } from "../deploy/constants";

/**
 * Verifies contracts on Etherscan.
 * @param deploymentInfo The deployment info file to use (optional) - defaults to core contract deployment info
 * @example npx hardhat verify-etherscan --deploymentInfo deployment-token-IB01.json --network mainnet
 */
task("verify-etherscan", "Verify contracts on Etherscan")
  .addOptionalParam("file", "The deployment info file to use", DEFAULT_FILENAME, types.string)
  .setAction(async function (taskArgs, hre) {
    const { file } = taskArgs;
    const networkName = hre.network.name;

    const deploymentInfo = await getDeploymentInfo(networkName, file);
    const allContractNames = Object.keys(deploymentInfo.contracts);

    const contracts = allContractNames.map(name => {
      const contract = deploymentInfo.contracts[name];
      return {
        name,
        address: contract.address,
        constructorArguments: contract.constructorArgs,
        libraries: contract.libraries,
        isProxy: contract.isProxy,
      };
    });
    console.log({ contracts });

    /* ---------------------- Verify Contracts on Etherscan --------------------- */

    for (const contract of contracts) {
      console.log(`Verifying contract: ${contract.name} at address: ${contract.address}`);
      let contractAddress = contract.address;

      try {
        // if contract is a proxy, get the implementation address
        // proxy contracts are verified automatically as the code is known to Etherscan
        if (contract?.isProxy) {
          const proxyAdmin = await hre.upgrades.admin.getInstance();
          const implementationAddress = await proxyAdmin.getProxyImplementation(contractAddress);
          console.log("Implementation address: ", implementationAddress);
          contractAddress = implementationAddress;
        }

        console.log("Verifying contract: ", contractAddress);
        console.log("With arguments: ", contract.constructorArguments);
        await hre.run("verify:verify", {
          address: contractAddress,
          constructorArguments: contract.constructorArguments,
          libraries: contract?.libraries,
        });
      } catch (e) {
        console.error(`Error verifying contract ${contract.name} ${contract.address} on Etherscan`);
        console.log(e);
      }
    }

    // TODO - add report
  });
