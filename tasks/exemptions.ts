import { task } from "hardhat/config";
import { executeRoleTransactions, log } from "../deploy/helpers";
import { getDeploymentInfo } from "../deploy/helpers";
import { ExemptionsManager } from "../src/types";
import { promises as fsp } from "fs";
import { RoleOperation } from "../deploy/types";

/**
 * Add global exemptions to ExemptionsManager based on list of addresses.
 * @notice relies on the `deploy` task to be run first to get the deployment info from the JSON file.
 * @notice This task is meant to be used after the `deploy` and before `owner` task.
 * @example npx hardhat exemptions --file-name example.json --description "example global exemption"
 */
task("exemptions", "Add exemptions to ExemptionsManager based on list of addresses")
  .addParam("fileName", "Name of the file containing the list of addresses")
  .addParam("description", "Description of the exemption")
  .setAction(async (taskArgs, hre) => {
    const { ethers, network } = hre;
    const [DEPLOYER] = await ethers.getSigners();
    const { fileName, description } = taskArgs;

    if (!fileName || !description) {
      throw new Error("Missing arguments. Please provide --file-name and --description");
    }

    log("ADDING EXEMPTIONS");

    /* ------------------------------- Grant Role ------------------------------- */
    const temporaryRoles = {
      ExemptionsManager: ["ROLE_GLOBAL_EXEMPTIONS_ADMIN"],
    };
    await executeRoleTransactions(hre, DEPLOYER.address, temporaryRoles, RoleOperation.Grant);

    /* ------------------------------ Add Exemptions ------------------------------ */
    const deploymentInfo = await getDeploymentInfo(network.name);
    const exemptionsManager = (await ethers.getContractAt(
      "ExemptionsManager",
      deploymentInfo.contracts.ExemptionsManager.address,
    )) as ExemptionsManager;

    const filePath = __dirname + "/../deploy/exemptions/" + fileName;
    console.log("Reading exemptions from: " + filePath);
    const exemptionsRaw = await fsp.readFile(filePath);
    const exemptions = JSON.parse(exemptionsRaw.toString());
    const addresses = exemptions.addresses;

    console.log("Adding exemptions...");

    // Add exemptions to ExemptionsManager based on list of addresses
    const tx = await exemptionsManager.admitGlobalExemption(addresses, description);
    await tx.wait();
    for (const address of addresses) {
      const isExempt = await exemptionsManager.isGlobalExemption(address);
      console.log(`Address ${address} is exempt: ${isExempt ? "✅ YES" : "🛑 NO"}`);
    }

    /* ------------------------------ Revoke Role ------------------------------ */
    await executeRoleTransactions(hre, DEPLOYER.address, temporaryRoles, RoleOperation.Renounce);
    console.log("Roles revoked");

    // TODO list print out all on-chain exemptions

    log("SUCCESSFULLY ADDED EXEMPTIONS");
  });
