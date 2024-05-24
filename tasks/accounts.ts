import { Signer } from "@ethersproject/abstract-signer";
import { task } from "hardhat/config";
import { namedAccounts } from "../test/constants";

task("accounts", "Prints the list of accounts", async (_taskArgs, hre) => {
  const accounts: Signer[] = await hre.ethers.getSigners();

  let i: number = 0;
  const user: string[] = Object.keys(namedAccounts);

  for (const account of accounts) {
    const accountName = user[i] ? "is " + user[i] : "(unused)";
    console.log(`[${i}] ${accountName}: ` + (await account.getAddress()));
    i = i + 1;
  }
});
