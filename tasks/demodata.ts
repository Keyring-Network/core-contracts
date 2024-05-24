import { task } from "hardhat/config";
import { RuleRegistry, PolicyManager, IdentityTree, WalletCheck } from "../src/types";
import { executeRoleTransactions, getDeploymentInfo } from "../deploy/helpers";
import { ATTESTOR_URI, BASE_RULES, RBD_REGIME_PUBLIC_KEYS, RULE_OPERATORS } from "../deploy/constants";
import { RoleOperation } from "../deploy/types";

interface ContractAddresses {
  ruleRegistry: string;
  policyManager: string;
  identityTree: string;
  walletCheck: string;
}

/**
 * This task is used to populate the contracts with demo data.
 * @notice This task is only meant to be used in a test environment.
 * @notice This task is meant to be used after the `deploy` and before `owner` task.
 * @example npx hardhat demodata
 */
task("demodata", "Populate contracts with demo data").setAction(async function (_, hre) {
  const { ethers, network } = hre;
  const [DEPLOYER] = await ethers.getSigners();

  const deploymentInfo = await getDeploymentInfo(network.name);

  const addresses: ContractAddresses = {
    ruleRegistry: deploymentInfo.contracts.RuleRegistry.address,
    policyManager: deploymentInfo.contracts.PolicyManager.address,
    identityTree: deploymentInfo.contracts.IdentityTree.address,
    walletCheck: deploymentInfo.contracts.WalletCheck.address,
  };

  const ruleRegistry = (await ethers.getContractAt("RuleRegistry", addresses.ruleRegistry)) as RuleRegistry;
  const policyManager = (await ethers.getContractAt("PolicyManager", addresses.policyManager)) as PolicyManager;
  const identityTree = (await ethers.getContractAt("IdentityTree", addresses.identityTree)) as IdentityTree;
  const walletCheck = (await ethers.getContractAt("WalletCheck", addresses.walletCheck)) as WalletCheck;

  /* ------------------------------- Grant Roles ------------------------------ */
  console.log("Granting temporary roles...");

  const temporaryRoles = {
    PolicyManager: [
      "ROLE_GLOBAL_ATTESTOR_ADMIN",
      "ROLE_GLOBAL_WALLETCHECK_ADMIN",
      "ROLE_POLICY_CREATOR",
      "ROLE_GLOBAL_BACKDOOR_ADMIN",
    ],
  };
  await executeRoleTransactions(hre, DEPLOYER.address, temporaryRoles, RoleOperation.Grant);
  // await waitForAllTransactions(grantRoleTransactions);
  console.log("Roles granted!");

  /* --------------------- Admit Attestor and WalletCheck --------------------- */

  console.log("admitting attestor and walletcheck...");

  const tx1 = await policyManager.admitAttestor(identityTree.address, ATTESTOR_URI);
  const tx2 = await policyManager.admitWalletCheck(walletCheck.address);
  await tx1.wait();
  await tx2.wait();

  console.log("contract Attestor and Walletcheck configuration confirmed");

  /* ------------------------------ Create Rules ------------------------------ */
  console.log("Creating rules...");

  const currentRuleCount = await ruleRegistry.ruleCount();

  for (const rule of BASE_RULES) {
    const ruleCount = (await ruleRegistry.ruleCount()).toString();
    const uri = rule.uri + ruleCount;
    console.log(rule.description, uri, rule.operator, rule.operands);
    const tx = await ruleRegistry.createRule(rule.description, uri, rule.operator, rule.operands);
    await tx.wait();
  }

  const numberOfRulesCreated = BASE_RULES.length;
  const newRuleIds = [];
  console.log(`Number of base rules created: ${numberOfRulesCreated}`);
  for (let i = 0; i < numberOfRulesCreated; i++) {
    const index = currentRuleCount.add(i);
    const rule = await ruleRegistry.ruleAtIndex(index);
    newRuleIds.push(rule);
    console.log(`Rule ID at index ${index}: ${rule}`);
  }

  // create complement expression rule
  const tx = await ruleRegistry.createRule("", "", RULE_OPERATORS.complement, [newRuleIds[0]]);
  await tx.wait();

  const ruleCount = await ruleRegistry.ruleCount();
  const expressionRuleId = await ruleRegistry.ruleAtIndex(ruleCount.sub(1));
  console.log(`Expression rule created with ID: ${expressionRuleId}`);

  /* ----------------------- Admit RBD Regime Public Key ---------------------- */

  for (const key of RBD_REGIME_PUBLIC_KEYS) {
    const _tx = await policyManager.admitBackdoor(key);
    await _tx.wait();
  }
  const globalBackdoorCount = await policyManager.globalBackdoorCount();
  console.log("Expected global backdoor count: ", RBD_REGIME_PUBLIC_KEYS.length);
  console.log("Actual global backdoor count: ", globalBackdoorCount.toString());

  /* ---------------------------- Deploy KYC Tokens --------------------------- */
  await hre.run("deploy-tokens", { token: "USDC", ruleId: expressionRuleId });
  // await hre.run("deploy-tokens", { token: "WETH", ruleId: expressionRuleId });
  // await hre.run("deploy-tokens", { token: "bIB01", ruleId: expressionRuleId });

  /* ------------------------------ Revoke Roles ------------------------------ */
  console.log("Revoking temporary roles...");
  await executeRoleTransactions(hre, DEPLOYER.address, temporaryRoles, RoleOperation.Renounce);
  console.log("Roles revoked!");

  console.log("Done!");
});
