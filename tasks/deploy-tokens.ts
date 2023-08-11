import { task, types } from "hardhat/config";
import { PolicyStorage } from "../src/types/PolicyManager";
import { IKeyringGuard } from "../src/types/KycERC20";
import { RuleRegistry, PolicyManager } from "../src/types";
import {
  deployContract,
  getAddresses,
  getCurrentCommitHash,
  getDeploymentInfo,
  log,
  writeDeploymentInfoToFile,
} from "../deploy/helpers";
import {
  MAXIMUM_CONSENT_PERIOD,
  ONE_DAY_IN_SECONDS,
  POLICY_DISABLEMENT_PERIOD,
  WRAPPED_TOKENS,
} from "../deploy/constants";
import { ContractList, DeploymentInfo } from "../deploy/types";

interface ContractAddresses {
  forwarder: string;
  ruleRegistry: string;
  policyManager: string;
  identityTree: string;
  walletCheck: string;
  keyringCredentials: string;
  userPolicies: string;
  exemptionsManager: string;
}

task("deploy-tokens", "Deploy KYC token")
  .addParam("token", "Token to deploy", "", types.string)
  .addOptionalParam("ruleId", "Rule ID to use for the token", "", types.string)
  .addOptionalParam("policyId", "Policy ID to use for the token", "", types.string)
  .setAction(async (taskArgs, hre) => {
    const { ethers, network } = hre;
    const { token, ruleId, policyId: _policyId } = taskArgs;
    console.log({ token, ruleId });

    const { ADMIN } = getAddresses(network.name);

    const contracts: ContractList[] = [];

    const selectedToken = WRAPPED_TOKENS[token];
    if (!selectedToken) {
      throw new Error(`Token ${token} not supported`);
    }

    const deploymentInfo = await getDeploymentInfo(network.name);

    const addresses: ContractAddresses = {
      ruleRegistry: deploymentInfo.contracts.RuleRegistry.address,
      policyManager: deploymentInfo.contracts.PolicyManager.address,
      identityTree: deploymentInfo.contracts.IdentityTree.address,
      walletCheck: deploymentInfo.contracts.WalletCheck.address,
      forwarder: deploymentInfo.contracts.KeyringMinimalForwarder.address,
      keyringCredentials: deploymentInfo.contracts.KeyringCredentials.address,
      userPolicies: deploymentInfo.contracts.UserPolicies.address,
      exemptionsManager: deploymentInfo.contracts.ExemptionsManager.address,
    };

    const ruleRegistry = (await ethers.getContractAt("RuleRegistry", addresses.ruleRegistry)) as RuleRegistry;
    const policyManager = (await ethers.getContractAt("PolicyManager", addresses.policyManager)) as PolicyManager;

    const timestamp = Date.now();
    const blockNumber = await ethers.provider.getBlockNumber();
    const commitHash = getCurrentCommitHash();
    console.log(`DEPLOYMENT HAS STARTED (timestamp: ${timestamp}, block: ${blockNumber})`);
    console.log("Current commit hash:", commitHash);

    const ruleExists = await ruleRegistry.isRule(ruleId);
    if (!ruleId || !ruleExists) {
      throw new Error(`No valid Rule ID provided`);
    }

    /* -------------------------- Deploy KycERC20 token ------------------------- */
    log("DEPLOY KYC TOKEN | " + token.toUpperCase());

    console.log({ selectedToken });
    console.log("Used rule: ", ruleId);

    /* ------------------------------ Deploy Policy ----------------------------- */

    let policyId = _policyId;

    if (!policyId) {
      const policyScalar: PolicyStorage.PolicyScalarStruct = {
        ruleId: ruleId,
        descriptionUtf8: `Admission Policy for KYC ${token} token`,
        ttl: ONE_DAY_IN_SECONDS,
        gracePeriod: 60, // 1 minute
        allowApprovedCounterparties: false,
        disablementPeriod: POLICY_DISABLEMENT_PERIOD,
        locked: false,
      };

      console.log("Create Policy:");
      console.log({ policyScalar });

      const tx = await policyManager.createPolicy(policyScalar, [addresses.identityTree], []);
      console.log("Waiting for Policy to be created...");
      await tx.wait();

      policyId = Number(await policyManager.policyCount()) - 1;
      console.log("Policy created! PolicyId: ", policyId);
    }

    /* ------------------------------ Deploy Tokens ----------------------------- */

    const KYC_TOKEN_NAME = `${selectedToken.name} (Compliance Policy: k${policyId})`; // {name} (Compliance Policy: k{policyNumber})
    const KYC_TOKEN_SYMBOL = `${selectedToken.symbol}.k${policyId}`; // {symbol}.k{policyNumber}

    console.log("KYC_TOKEN_NAME: ", KYC_TOKEN_NAME);
    console.log("KYC_TOKEN_SYMBOL: ", KYC_TOKEN_SYMBOL);

    const keyringGuardconfig: IKeyringGuard.KeyringConfigStruct = {
      trustedForwarder: addresses.forwarder,
      collateralToken: selectedToken.address,
      keyringCredentials: addresses.keyringCredentials,
      policyManager: policyManager.address,
      userPolicies: addresses.userPolicies,
      exemptionsManager: addresses.exemptionsManager,
    };

    const constructorArgs = [keyringGuardconfig, policyId, MAXIMUM_CONSENT_PERIOD, KYC_TOKEN_NAME, KYC_TOKEN_SYMBOL];
    const { contract: kycERC20, factory: kycERC20Factory } = await deployContract("KycERC20", constructorArgs, hre);
    contracts.push({ name: KYC_TOKEN_SYMBOL, contract: kycERC20, factory: kycERC20Factory, constructorArgs });

    console.log(`Address for wrapped kyc token ${KYC_TOKEN_NAME}: ${kycERC20.address}`);
    console.log("Waiting for KycERC20 to be deployed...");
    await kycERC20.deployed();
    console.log("KycERC20 deployed!");

    /* ---------------------------------- DONE ---------------------------------- */

    log("KYC TOKEN DEPLOYED | " + token.toUpperCase());

    const deploymentInfoTokens: DeploymentInfo = {
      blockNumber: blockNumber,
      commitHash: commitHash,
      roles: [
        {
          name: "Default Admin",
          address: "",
          granted: {},
        },
      ],
      tokenInfo: {
        ...selectedToken,
        kycName: KYC_TOKEN_NAME,
        kycSymbol: KYC_TOKEN_SYMBOL,
      },
      contracts: {},
    };

    for (const { name, contract, factory, constructorArgs } of contracts) {
      deploymentInfoTokens.contracts[name] = {
        address: contract.address,
        abi: JSON.parse(factory.interface.format("json") as string),
        constructorArgs: constructorArgs || [],
        isProxy: false,
      };
    }

    writeDeploymentInfoToFile(deploymentInfoTokens, undefined, `deployment-token-${token}.json`, network.name);
  });
