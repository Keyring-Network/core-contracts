import { task } from "hardhat/config";
import { executeRoleTransactions, getAddresses, getDeploymentInfo, writeDeploymentInfoToFile } from "../deploy/helpers";
import {
  ADMIN_CONTRACT_ROLES,
  AGGREGATOR_CONTRACT_ROLES,
  WALLET_CHECK_CONTRACT_ROLES,
  CREDENTIAL_UPDATER_1_CONTRACT_ROLES,
} from "../deploy/roles";
import { RoleOperation } from "../deploy/types";
import { log } from "../deploy/helpers";

/**
 * Transfer ownership of all contracts and ProxyAdmin owner to the `ADMIN` address.
 * Transfer specific roles to the `AGGREGATOR` and `WALLET_CHECK` addresses.
 * Revokes the `Deployer` from all roles.
 * @notice relies on the `deploy` task to be run first to get the deployment info from the JSON file.
 * @example npx hardhat owner
 */
task("owner", "Transfer ownership of contract roles").setAction(async function (_, hre) {
  const { ethers, network, upgrades } = hre;
  const [DEPLOYER] = await ethers.getSigners();
  const { ADMIN, AGGREGATOR, WALLET_CHECK } = getAddresses(network.name);
  const deploymentInfo = await getDeploymentInfo(network.name);

  const CREDENTIAL_UPDATER_1 = deploymentInfo.contracts.KeyringZkCredentialUpdater.address;

  console.log("START TRANSFERING OWNERSHIP");
  console.log("FROM DEPLOYER:", DEPLOYER.address);
  console.log("TO ADMIN:", ADMIN);
  console.log("TO AGGREGATOR:", AGGREGATOR);
  console.log("TO WALLET_CHECK:", WALLET_CHECK);

  /* ----------------------------- Granting Roles ----------------------------- */
  log("GRANTING ROLES TO ADMIN");
  console.log("ADMIN:", ADMIN);
  const { roleDetails: grantedAdminRoles } = await executeRoleTransactions(
    hre,
    ADMIN,
    ADMIN_CONTRACT_ROLES,
    RoleOperation.Grant,
  );

  // Aggregator
  log("GRANTING ROLES TO AGGREGATOR");
  console.log("AGGREGATOR:", AGGREGATOR);
  const { roleDetails: grantedAggregator1Roles } = await executeRoleTransactions(
    hre,
    AGGREGATOR,
    AGGREGATOR_CONTRACT_ROLES,
    RoleOperation.Grant,
  );

  log("GRANTING ROLES TO WALLET_CHECK");
  console.log("WALLET_CHECK:", WALLET_CHECK);
  const { roleDetails: grantedAggregator2Roles } = await executeRoleTransactions(
    hre,
    WALLET_CHECK,
    WALLET_CHECK_CONTRACT_ROLES,
    RoleOperation.Grant,
  );

  log("GRANTING ROLES TO CREDENTIAL_UPDATER_1");
  console.log("CREDENTIAL_UPDATER_1:", CREDENTIAL_UPDATER_1);
  const { roleDetails: grantedCredentialUpdater1Roles } = await executeRoleTransactions(
    hre,
    CREDENTIAL_UPDATER_1,
    CREDENTIAL_UPDATER_1_CONTRACT_ROLES,
    RoleOperation.Grant,
  );

  /* ---------------------------- Revoke Deployer Roles --------------------------- */
  // TODO - move this to a separate task to avoid mistakes
  // log("REVOKING DEPLOYER ROLES");
  // await executeRoleTransactions(hre, DEPLOYER.address, DEPLOYER_CONTRACT_ROLES, RoleOperation.Renounce);

  /* ----------------------- Transfer Proxy Admin Owner ----------------------- */
  log("TRANSFERING PROXY ADMIN OWNER");
  const proxyAdmin = await upgrades.admin.getInstance();
  const oldProxyAdminOwner = await proxyAdmin.owner();
  await upgrades.admin.transferProxyAdminOwnership(ADMIN);
  const newProxyAdminOwner = await proxyAdmin.owner();
  console.log("Proxy admin ownership transfered successfully from", oldProxyAdminOwner, "to", newProxyAdminOwner);

  /* ------------------------- Update Deployment Info ------------------------- */
  deploymentInfo.roles[1].address = ADMIN;
  deploymentInfo.roles[1].granted = grantedAdminRoles;
  deploymentInfo.roles.push({
    name: "ProxyAdmin Owner",
    address: ADMIN,
    granted: {
      ProxyAdmin: [
        {
          name: "Owner",
          id: "",
        },
      ],
    },
  });
  deploymentInfo.roles.push({
    name: "Keyring_Aggregator",
    address: AGGREGATOR,
    granted: grantedAggregator1Roles,
  });
  deploymentInfo.roles.push({
    name: "Keyring_WalletCheck",
    address: WALLET_CHECK,
    granted: grantedAggregator2Roles,
  });
  deploymentInfo.roles.push({
    name: "CredentialUpdater_1",
    address: CREDENTIAL_UPDATER_1,
    granted: grantedCredentialUpdater1Roles,
  });

  writeDeploymentInfoToFile(deploymentInfo, undefined, undefined, network.name);

  console.log("END TRANSFERING OWNERSHIP");
});
