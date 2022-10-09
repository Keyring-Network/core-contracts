import { ethers } from "hardhat";
import { expect } from "chai";

import { MockERC20 } from "../../src/types";

const tokenName = "Mock ERC20 token";
const tokenSymbol = "MERC20";
const tokenSupply = 10000;

/* -------------------------------------------------------------------------- */
/*             Test to ensure that the MockERC20 deploys properly.            */
/* -------------------------------------------------------------------------- */

describe("Mock ERC20", function () {
  describe("Deployment", function () {
    it("should be ready to test", async function () {
      expect(true).to.equal(true);
    });

    it("should not deploy invalid ERC20 tokens", async function () {
      const reason1 = "MockERC20:constructor: name cannot be empty";
      const reason2 = "MockERC20:constructor: symbol cannot be empty";
      const reason3 = "MockERC20:constructor: supply cannot be zero";

      await expect(deployMockERC20("", tokenSymbol, tokenSupply)).to.be.revertedWith(reason1);

      await expect(deployMockERC20(tokenName, "", tokenSupply)).to.be.revertedWith(reason2);

      await expect(deployMockERC20(tokenName, tokenSymbol, 0)).to.be.revertedWith(reason3);
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

const deployMockERC20 = async function (tokenName: string, tokenSymbol: string, tokenSupply: number) {
  const MockERC20Factory = await ethers.getContractFactory("MockERC20");
  const mockERC20 = (await MockERC20Factory.deploy(tokenName, tokenSymbol, tokenSupply)) as MockERC20;
  await mockERC20.deployed();
  return mockERC20;
};
