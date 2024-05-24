import { task } from "hardhat/config";
import { log } from "../deploy/helpers";
import { getAddresses } from "../deploy/helpers";

/**
 * This task will run all tasks in order:
 * 1. deploy
 * 2. demodata
 * 3. owner
 * 4. hasRoles
 * @notice This task is only meant to be used in a test environment.
 * @example npx hardhat deploy-demodata-owner
 */
task("deploy-demodata-owner", "Run all tasks", async (_, hre) => {
  const [DEPLOYER] = await hre.ethers.getSigners();
  const { ADMIN } = getAddresses(hre.network.name);

  log("RUN DEPLOY");
  await hre.run("deploy");
  log("RUN DEMODATA");
  await hre.run("demodata");
  log("RUN EXEMPTIONS");
  await hre.run("exemptions", { fileName: "example.json", description: "example global exemption" });
  log("RUN OWNER");
  await hre.run("owner");
  log("RUN HASROLES");
  await hre.run("hasRoles", { account: ADMIN, isAdmin: true });
  await hre.run("hasRoles", { account: DEPLOYER.address });
  log("ALL TASKS DONE");
});
