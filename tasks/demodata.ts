import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/dist/src/signer-with-address";
import { ethers } from "hardhat";
import { task } from "hardhat/config";
import { TaskArguments } from "hardhat/types";
import { PolicyStorage } from "../src/types/PolicyManager";
import { baseRules, ONE_DAY_IN_SECONDS, Operator, proofMerkleRoot, THIRTY_DAYS_IN_SECONDS } from "../constants";
import { RuleRegistry, PolicyManager } from "../src/types";

const fsp = require("fs").promises;
const fs = require("fs");

const contractsDir = __dirname + "/../deploymentInfo";

export interface Signers {
  admin: SignerWithAddress;
}

interface ContractAddresses {
  ruleRegistry: string;
  policyManager: string;
}

task("demodata").setAction(async function (taskArguments: TaskArguments, { ethers }) {
  let signers = {} as Signers;
  const walletSigners: SignerWithAddress[] = await ethers.getSigners();
  signers.admin = walletSigners[0];

  const deploymentInfo = await getDeploymentInfo();

  const addresses: ContractAddresses = {
    ruleRegistry: deploymentInfo.contracts.RuleRegistry.address,
    policyManager: deploymentInfo.contracts.PolicyManager.address,
  };

  const ruleRegistry = (await ethers.getContractAt("RuleRegistry", addresses.ruleRegistry)) as RuleRegistry;
  const policyManager = (await ethers.getContractAt("PolicyManager", addresses.policyManager)) as PolicyManager;

  /* ------------------------------ Create Rules ------------------------------ */

  console.log("Creating rules...");
  // creating six rules, three base rules and three expression rules (complement, union, intersection)
  // start by creating three base rules and retrieve ruleId's
  const tx1 = await ruleRegistry.createRule(...baseRules.PP_GB);
  await tx1.wait();
  const tx2 = await ruleRegistry.createRule(...baseRules.PP_US);
  await tx2.wait();
  const tx3 = await ruleRegistry.createRule(...baseRules.PEP);
  await tx3.wait();
  const RULE_ID_PP_GB = await ruleRegistry.ruleAtIndex(2);
  const RULE_ID_PP_US = await ruleRegistry.ruleAtIndex(3);
  const RULE_ID_PEP = await ruleRegistry.ruleAtIndex(4);

  // sorting ruleId's in acending order as required
  let sortedRules = sortAscendingOrder([RULE_ID_PP_GB, RULE_ID_PP_US]);

  // create two expression rules and retrieve ruleId's
  const tx4 = await ruleRegistry.createRule("", "", Operator.complement, [RULE_ID_PEP]);
  await tx4.wait();
  const tx5 = await ruleRegistry.createRule("", "", Operator.union, sortedRules);
  await tx5.wait();
  const RULE_ID_UNION_GB_US = await ruleRegistry.ruleAtIndex(5);
  const RULE_ID_COMPLEMENT_PEP = await ruleRegistry.ruleAtIndex(6);

  // create another expression rule based on the previous two rules
  sortedRules = sortAscendingOrder([RULE_ID_UNION_GB_US, RULE_ID_COMPLEMENT_PEP]);
  const tx6 = await ruleRegistry.createRule("", "", Operator.intersection, sortedRules);
  await tx6.wait();

  const RULE_ID_GBUS_EXCL_PEP = await ruleRegistry.ruleAtIndex(7);

  console.log("Successfully created 6 rules!");

  /* ------------------------------ Create Policy ----------------------------- */
  const policyScalar: PolicyStorage.PolicyScalarStruct = {
    ruleId: RULE_ID_GBUS_EXCL_PEP,
    descriptionUtf8: "Intersection: Union [ GB, US ], Complement [ PEP ] - 1 of 2",
    ttl: ONE_DAY_IN_SECONDS,
    gracePeriod: THIRTY_DAYS_IN_SECONDS,
    acceptRoots: 1,
    locked: false,
    allowUserWhitelists: false,
  };

  const policyCount = await policyManager.policyCount();
  console.log("Policy count: " + policyCount);

  // NOTE Buluts Attestor address
  const attestorAddress = "0xbF76cca6D678949E207D7fB66136bbFdd4E317aF";
  const walletcheckAddress = deploymentInfo.contracts.WalletCheck.address;

  // create policy with ID 1 to 20
  const policies = <any>[];
  for (let i = 1; i <= 20; i++) {
    // console.log("Creating policy with ID: " + i);
    policies.push(await policyManager.createPolicy(policyScalar, [attestorAddress], [walletcheckAddress]));
  }

  await Promise.all(policies).then(() => {
    for (let i = 0; i < policies.length; i++) {
      policies[i].wait().then(() => {
        // nothing to do
      });
    }
  });

  console.log("Done!");
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

// NOTE instead of `1675276993802` set timestamp of latest deployment
async function getDeploymentInfo() {
  var result = fs.readdirSync(contractsDir).sort().reverse();
  var subdir = result[0];
  console.log("Reading DeploymentInfo from: " + contractsDir + "/" + subdir + "/deployment.json");
  const deploymentInfo = await fsp.readFile(contractsDir + "/" + subdir + "/deployment.json");
  return JSON.parse(deploymentInfo);
}

function sortAscendingOrder(ruleIds: string[]) {
  return ruleIds.sort();
}
