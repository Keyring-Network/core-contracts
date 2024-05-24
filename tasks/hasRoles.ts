import { task, types } from "hardhat/config";
import { getDeploymentDir, getDeploymentInfo, getRoleID, hasRole } from "../deploy/helpers";
import { log } from "../deploy/helpers";
import { ALL_CONTRACT_NAMES, DEFAULT_FILENAME } from "../deploy/constants";
import { ADMIN_CONTRACT_ROLES, ALL_CONTRACT_ROLES } from "../deploy/roles";

/**
 * Check which roles are assigned to the given address for all contracts.
 * If `isAdmin` is true, check if the address has the specific admin role,
 * otherwise check against all contract roles.
 * @example npx hardhat hasRoles --account 0x1234567890123456789012345678901234567890 --is-admin true
 */
task("hasRoles", "Check which roles are assigned to the given address")
  .addParam("account", "The address of the account to check")
  .addOptionalParam("isAdmin", "Check if the account is admin", false, types.boolean)
  .addOptionalParam("deploymentId", "ID of the existing deployment to use as base", "", types.string)
  .setAction(async (taskArgs, hre) => {
    const { account, isAdmin, deploymentId } = taskArgs;

    const deploymentInfo = await getDeploymentInfo(
      hre.network.name,
      DEFAULT_FILENAME,
      deploymentId ? getDeploymentDir(hre.network.name, deploymentId) : undefined
    );

    const contracts = ALL_CONTRACT_NAMES.map(name => ({
      name: name,
      address: deploymentInfo.contracts[name].address,
    }));

    log("CHECKING ROLES");
    console.log("ACCOUNT:", account);
    console.log("IS ADMIN:", isAdmin);
    console.log("\n");

    for (const contract of contracts) {
      const contractRoles = isAdmin ? ADMIN_CONTRACT_ROLES[contract.name] : ALL_CONTRACT_ROLES[contract.name];
      if (contractRoles) {
        console.log(`▶️ ${contract.name} (${contract.address})`);
        for (const role of contractRoles) {
          const _hasRole = await hasRole(hre, contract.name, contract.address, role, account);
          console.log(`${role} (${getRoleID(role)}): ${_hasRole ? "✅ YES" : "🛑 NO"}`);
        }
        console.log("\n");
      } else {
        console.log(`❌ ${contract.name} (${contract.address})`);
        console.log("\n");
      }
    }

    // Proxy admin
    const proxyAdmin = await hre.upgrades.admin.getInstance();
    const proxyAdminOwner = await proxyAdmin.owner();
    const isProxyAdmin = account.toLowerCase() === proxyAdminOwner.toLowerCase();
    console.log(`▶️ ProxyAdmin (${proxyAdmin.address})`);
    console.log(`OWNER: ${isProxyAdmin ? "✅ YES" : "🛑 NO"}`);

    log("DONE CHECKING ROLES");
  });
