import { JsonRpcProvider } from "@ethersproject/providers";
import { BigNumber, ethers } from "ethers";
import { task, types } from "hardhat/config";
import { exit } from "process";
import { log } from "../deploy/helpers";

/**
 * This task is used to check if the deployer has enough funds to perform transactions.
 * It also calculates the total cost and time taken to execute the given task.
 * Optionally, you can override the gas price and gas usage for a task.
 * Gas price is in wei and default is the current gas price at the time of execution.
 * Gas usage default is the known gas usage for the given task (see getKnownGasUsagePerTask()).
 * @example npx hardhat gas --task-name deploy
 * @example npx hardhat gas --gas-price 20 --gas-usage 22498322 --task-name deploy
 */
task("gas", "Gas checker task as wrapper for other tasks")
  .addOptionalParam("gasPrice", "The gas price used to calculate the total gas cost (in Gwei)", "", types.string)
  .addOptionalParam("gasUsage", "The gas usage for transactions of the task", "", types.string)
  .addParam("taskName", "The name of the task to execute")
  .setAction(async (taskArgs, hre) => {
    const [DEPLOYER] = await hre.ethers.getSigners();
    const gasPriceGwei = taskArgs.gasPrice;
    const gasPriceWeiStart = gasPriceGwei
      ? ethers.utils.parseUnits(gasPriceGwei, "gwei")
      : await hre.ethers.provider.getGasPrice();
    const task = taskArgs.taskName;
    const gasUsage = ethers.BigNumber.from(taskArgs.gasUsage || getKnownGasUsagePerTask(task));

    // Preliminary check for deployer's balance
    log("CHECK FUNDS OF DEPLOYER");
    if (!(await hasEnoughFunds(hre.ethers.provider, DEPLOYER.address, gasPriceWeiStart, gasUsage))) {
      console.error("Not enough funds to deploy this contract.");
      exit(1);
    } else {
      console.log("Enough funds to deploy this contract.");
    }

    // Calculate total cost and time before executing the task
    const balanceBefore = await hre.ethers.provider.getBalance(DEPLOYER.address);
    const timeBefore = Date.now();

    // Execute the given task
    log(`RUN TASK: ${task.toUpperCase()}`);
    await hre.run(task);

    // Calculate total cost and time after executing the task
    log("CALCULATE GAS COST AND TIME TAKEN");
    const balanceAfter = await hre.ethers.provider.getBalance(DEPLOYER.address);
    const timeAfter = Date.now();

    // Calculate the total cost, estimate gas used and time taken
    const totalCost = balanceBefore.sub(balanceAfter);
    const timeTaken = timeAfter - timeBefore;
    const timeTakenInSeconds = timeTaken / 1000;
    const gasPriceWeiEnd = gasPriceGwei ? gasPriceWeiStart : await hre.ethers.provider.getGasPrice();
    const avgGasPrice = gasPriceWeiStart.add(gasPriceWeiEnd).div(2);
    const estimatedGasUsed = totalCost.div(avgGasPrice);

    console.log(`Balance before: ${hre.ethers.utils.formatEther(balanceBefore)} ETH`);
    console.log(`Balance after: ${hre.ethers.utils.formatEther(balanceAfter)} ETH`);
    console.log(`Total cost: ${hre.ethers.utils.formatEther(totalCost)} ETH (balanceBefore - balanceAfter)`);
    console.log(`Estimated gas used: ${estimatedGasUsed} (totalCost / gasPrice)`);
    console.log(`Assumed avg. gas price: ${avgGasPrice} wei`);
    console.log(`Time taken: ${timeTakenInSeconds} seconds`);
  });

/* ---------------------------- HELPER FUNCTIONS ---------------------------- */

/**
 * @param taskName The name of the task
 * @returns The `gas` usage for transactions of the task if known, otherwise empty string
 * NOTE - Numbers are not reliable as they come from one goerli deployment
 */
const getKnownGasUsagePerTask = (taskName: string): string => {
  switch (taskName) {
    case "deploy":
      return "30783079"; // goerli: 30783079
    case "demodata":
      return "1939175"; // goerli: x
    case "owner":
      return "1939175"; // goerli: 1939175
    case "deploy-demodata-owner":
      return "29585542"; // goerli: x
    default:
      return "";
  }
};

/**
 * @param provider The JsonRpc provider to use
 * @param address The address to check the balance of
 * @param gasPrice Gas price used to calculate the total gas cost (in wei)
 * @param gasUsage Gas usage for transactions
 * @returns true if the deployer has enough funds to perform transactions
 */
const hasEnoughFunds = async (provider: JsonRpcProvider, address: string, gasPrice: BigNumber, gasUsage: BigNumber) => {
  const balance = await provider.getBalance(address);
  const bufferInPercent = 20; // 20% buffer for gas price fluctuations
  const estimatedCost = gasUsage.mul(gasPrice);
  const estimatedCostWithBuffer = estimatedCost.mul(100 + bufferInPercent).div(100);
  const canDeploy = balance.gte(estimatedCostWithBuffer);
  console.log(`Balance: ${ethers.utils.formatEther(balance)} ETH`);
  console.log(`Assumed gas price: ${gasPrice} wei / ${ethers.utils.formatUnits(gasPrice, "gwei")} gwei `);
  console.log(`Assumed gas usage: ${gasUsage}`);
  console.log(`Estimated cost: ${ethers.utils.formatEther(estimatedCost)} ETH`);
  console.log(`Estimated cost with buffer: ${ethers.utils.formatEther(estimatedCostWithBuffer)} ETH`);
  console.log(`Can deploy: ${canDeploy}`);
  return canDeploy;
};
