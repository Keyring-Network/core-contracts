import { getDeploymentInfo } from "../../deploy/helpers";
import { expect } from "chai";
const hre = require("hardhat");

describe("Upgrade Task", () => {
  let data: any;
  before(async () => {
    await hre.run("deploy");
    data = await getDeploymentInfo(hre.network.name);
  });

  const someAddress1 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const someAddress2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  const someNumber = 100000;

  it("should upgrade KeyringCredentials", async () => {
    const constructorArgs = JSON.stringify([someAddress1, someAddress2, someNumber]);
    await hre.run("upgrade", { contract: "KeyringCredentials", args: constructorArgs });
    const credentials = await hre.ethers.getContractAt(
      "KeyringCredentials",
      data.contracts["KeyringCredentials"].address,
    );
    expect(await credentials.isTrustedForwarder(someAddress1)).to.equal(true);
    expect(await credentials.policyManager()).to.equal(someAddress2);
    expect(await credentials.maximumConsentPeriod()).to.equal(someNumber);
  });

  it("should upgrade RuleRegistry", async () => {
    const constructorArgs = JSON.stringify([someAddress1]);
    await hre.run("upgrade", { contract: "RuleRegistry", args: constructorArgs });
    const ruleRegistry = await hre.ethers.getContractAt("RuleRegistry", data.contracts["RuleRegistry"].address);
    expect(await ruleRegistry.isTrustedForwarder(someAddress1)).to.equal(true);
  });

  it("should upgrade UserPolicies", async () => {
    const constructorArgs = JSON.stringify([someAddress1, someAddress2]);
    await hre.run("upgrade", { contract: "UserPolicies", args: constructorArgs });
    const userPolicies = await hre.ethers.getContractAt("UserPolicies", data.contracts["UserPolicies"].address);
    expect(await userPolicies.isTrustedForwarder(someAddress1)).to.equal(true);
    expect(await userPolicies.policyManager()).to.equal(someAddress2);
  });

  it("should upgrade PolicyManager", async () => {
    const constructorArgs = JSON.stringify([someAddress1, someAddress2]);
    const libraries = JSON.stringify(["PolicyStorage"]);
    await hre.run("upgrade", { contract: "PolicyManager", args: constructorArgs, libraries: libraries });
    const policyManager = await hre.ethers.getContractAt("PolicyManager", data.contracts["PolicyManager"].address);
    expect(await policyManager.isTrustedForwarder(someAddress1)).to.equal(true);
    expect(await policyManager.ruleRegistry()).to.equal(someAddress2);
  });

  it("should upgrade forwarder", async () => {
    await hre.run("upgrade", { contract: "NoImplementation", proxyName: "KeyringMinimalForwarder" });
  });

  it("should upgrade ExemptionsManager", async () => {
    const constructorArgs = JSON.stringify([someAddress1]);
    await hre.run("upgrade", { contract: "ExemptionsManager", args: constructorArgs });
    const exemptionsManager = await hre.ethers.getContractAt(
      "ExemptionsManager",
      data.contracts["ExemptionsManager"].address,
    );
    expect(await exemptionsManager.isTrustedForwarder(someAddress1)).to.equal(true);
  });

  // NOTE - Contracts below are not upgradeable, uncomment if needed
  /*
    it("should upgrade KeyringZkVerifier", async () => {
        const constructorArgs = JSON.stringify([someAddress1, someAddress2, someAddress3]);
        console.log(constructorArgs);
        await hre.run("upgrade", {contract: "KeyringZkVerifier", args: constructorArgs});
        const keyringZkVerifier = await hre.ethers.getContractAt("KeyringZkVerifier", data.contracts["KeyringZkVerifier"].address);
        expect(await keyringZkVerifier.IDENTITY_CONSTRUCTION_PROOF_VERIFIER()).to.equal(someAddress1);
        expect(await keyringZkVerifier.IDENTITY_MEMBERSHIP_PROOF_VERIFIER()).to.equal(someAddress2);
        expect(await keyringZkVerifier.AUTHORIZATION_PROOF_VERIFIER()).to.equal(someAddress3);
    });
    */

  /*
    it("should upgrade WalletCheck", async () => {
        const constructorArgs = JSON.stringify([someAddress, someAddress, someNumber, "some uri"]);
        hre.run("upgrade", {network: "localhost", contract: "WalletCheck", args: constructorArgs});
    });

    it("should upgrade IdentityTree", async () => {
        const constructorArgs = JSON.stringify([someAddress, someAddress, someNumber]);
        hre.run("upgrade", {network: "localhost", contract: "IdentityTree", args: constructorArgs});
    });
    */
});
