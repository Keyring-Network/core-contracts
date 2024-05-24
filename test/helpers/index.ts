import { BigNumber, utils } from "ethers";
import { PolicyManager } from "../../src/types";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";

export const unacceptable = (reason: string) => {
  return `Unacceptable("${reason}")`;
};

export const unauthorized = (
  sender: string,
  module: string,
  method: string,
  role: string,
  reason: string,
  context: string,
) => {
  return `Unauthorized("${sender}", "${module}", "${method}", "${role}", "${reason}", "${context}")`;
};

function flatten_struct(struct: { [key: string]: any }): string[] {
  let result: string[] = [];
  for (const key in struct) {
    if (typeof struct[key] === "object") {
      result = result.concat(flatten_struct(struct[key]));
    } else {
      result.push(struct[key]);
    }
  }
  return result;
}

export const applyPolicyChanges = async (policyManager: PolicyManager, policyId: number) => {
  const policyObj = await policyManager.callStatic.policy(policyId);
  await helpers.time.increaseTo(policyObj.deadline.toNumber());
  await policyManager.policy(policyId);
};

export const constructProofVerifierInputs = (proof: any, invalidateProof?: boolean) => {
  const inputs = flatten_struct(Object.assign({}, proof, { proof: undefined })).slice(1) as string[];
  if (invalidateProof) inputs[1] = "0x".padEnd(64, "0");
  return inputs;
};

export function sortAscendingOrder(ruleIds: string[]) {
  return ruleIds.sort();
}

export const walletCheckKeyGen = (subject: string) => {
  const subjectBN = BigNumber.from(subject);
  const subjectBytes32 = utils.hexZeroPad(subjectBN.toHexString(), 32);
  return subjectBytes32;
};
