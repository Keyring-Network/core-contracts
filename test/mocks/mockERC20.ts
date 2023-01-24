import { ethers } from "hardhat";
import { expect } from "chai";

import { MockERC20 } from "../../src/types";

const TOKEN_NAME = "Mock ERC20 token";
const TOKEN_SYMBOL = "MERC20";
const TOKEN_SUPPLY = 10000;

/* -------------------------------------------------------------------------- */
/*             Test to ensure that the MockERC20 deploys properly.            */
/* -------------------------------------------------------------------------- */

describe("Mock ERC20", function () {
  describe("Deployment", function () {
    it("should not deploy invalid ERC20 tokens", async function () {
      const reason1 = "MockERC20:constructor: name cannot be empty";
      const reason2 = "MockERC20:constructor: symbol cannot be empty";
      const reason3 = "MockERC20:constructor: supply cannot be zero";

      await expect(deployMockERC20("", TOKEN_SYMBOL, TOKEN_SUPPLY)).to.be.revertedWith(reason1);

      await expect(deployMockERC20(TOKEN_NAME, "", TOKEN_SUPPLY)).to.be.revertedWith(reason2);

      await expect(deployMockERC20(TOKEN_NAME, TOKEN_SYMBOL, 0)).to.be.revertedWith(reason3);
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

const deployMockERC20 = async function (TOKEN_NAME: string, TOKEN_SYMBOL: string, TOKEN_SUPPLY: number) {
  const MockERC20Factory = await ethers.getContractFactory("MockERC20");
  const mockERC20 = (await MockERC20Factory.deploy(TOKEN_NAME, TOKEN_SYMBOL, TOKEN_SUPPLY)) as MockERC20;
  await mockERC20.deployed();
  return mockERC20;
};
