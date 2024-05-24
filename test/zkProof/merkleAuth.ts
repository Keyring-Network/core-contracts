import { Signer } from "ethers";
import { createFixtureLoader } from "ethereum-waffle";
import { getNamedAccounts, ethers, waffle } from "hardhat";
import { expect } from "chai";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import { keyringTestFixture } from "../shared/fixtures";
import { PolicyStorage } from "../../src/types/PolicyManager";
import type {
  KeyringCredentials,
  PolicyManager,
  WalletCheck,
  IdentityTree,
  IdentityTree__factory,
  MerkleAuthVerifier,
  KeyringMerkleAuthZkCredentialUpdater,
  KeyringMerkleAuthZkVerifier,
} from "../../src/types";
import { MAXIMUM_CONSENT_PERIOD, namedAccounts, THIRTY_DAYS_IN_SECONDS } from "../constants";
import {
  ZK_PROOF_NUM,
  ZK_PROOF_RELEASE,
  ZK_PROOF_TYPE,
  getProof,
  getTrader,
  getTraderSigner,
} from "../constants/zkProofs";
import { constructProofVerifierInputs, unacceptable, applyPolicyChanges } from "../helpers";

/* -------------------------------------------------------------------------- */
/* Test to ensure that Zero Knowledge related contracts are working properly  */
/* -------------------------------------------------------------------------- */

describe("Zero-knowledge | Merkle Auth", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];

  // prepare contracts with interfaces
  let credentials: KeyringCredentials;
  let policyManager: PolicyManager;
  let credentialsUpdater: KeyringMerkleAuthZkCredentialUpdater;
  let walletCheck: WalletCheck;
  let identityTree: IdentityTree;
  let merkleAuthProofVerifier: MerkleAuthVerifier;
  let keyringMerkleAuthZkVerifier: KeyringMerkleAuthZkVerifier;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  // policy struct to be used in tests
  let policyScalar: PolicyStorage.PolicyScalarStruct;

  // accounts in this test
  let admin: string;
  let traderAsSigner0: Signer;
  let attacker: string;
  let attackerAsSigner: Signer;

  // proofs
  const Authorisation_00 = getProof(ZK_PROOF_TYPE.MERKLE_AUTH, ZK_PROOF_NUM.zero, ZK_PROOF_RELEASE["2023-12-19.1"]);
  // const Authorisation_01 = getProof(ZK_PROOF_TYPE.MERKLE_AUTH, ZK_PROOF_NUM.one, ZK_PROOF_RELEASE["2023-12-19.1"]);
  // const Authorisation_02 = getProof(ZK_PROOF_TYPE.MERKLE_AUTH, ZK_PROOF_NUM.two, ZK_PROOF_RELEASE["2023-12-19.1"]);

  // traders
  const trader0 = getTrader(ZK_PROOF_NUM.zero, ZK_PROOF_RELEASE["2023-12-19.1"]);
  // const trader1 = getTrader(ZK_PROOF_NUM.one, ZK_PROOF_RELEASE["2023-12-19.1"]);

  before(async () => {
    const { admin: adminAddress, attacker: attackerAddress } = await getNamedAccounts();
    admin = adminAddress;
    // `attacker` connect's with contract and try to sign invalid
    attacker = attackerAddress;
    attackerAsSigner = ethers.provider.getSigner(attacker);
    // set up trader wallets with 2000 ETH each
    traderAsSigner0 = getTraderSigner(provider, ZK_PROOF_NUM.zero, ZK_PROOF_RELEASE["2023-12-19.1"]);
    await adminWallet.sendTransaction({ to: trader0.address, value: ethers.utils.parseEther("2000") });
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  beforeEach(async function () {
    // load pre-configured contracts
    const fixture = await loadFixture(keyringTestFixture);
    credentials = fixture.contracts.credentials;
    policyManager = fixture.contracts.policyManager;
    credentialsUpdater = fixture.contracts.keyringMerkleAuthZkCredentialUpdater;
    walletCheck = fixture.contracts.walletCheck;
    identityTree = fixture.contracts.identityTree;
    merkleAuthProofVerifier = fixture.contracts.merkleAuthProofVerifier;
    keyringMerkleAuthZkVerifier = fixture.contracts.keyringMerkleAuthZkVerifier;

    policyScalar = fixture.policyScalar;
  });

  describe("Verify Merkle Auth Proofs", function () {
    it("should return true for valid proofs", async function () {
      const result = await merkleAuthProofVerifier.verifyProof(
        Authorisation_00.proof.a,
        Authorisation_00.proof.b,
        Authorisation_00.proof.c,
        constructProofVerifierInputs(Authorisation_00),
      );
      expect(result, "merkleAuthProofVerifier.verifyProof").to.be.equal(true);

      const result2 = await keyringMerkleAuthZkVerifier.checkClaim(Authorisation_00);
      expect(result2, "keyringMerkleAuthZkVerifier.verifyProof").to.be.equal(true);
    });
    it("should return false for invalid proofs", async function () {
      const result = await merkleAuthProofVerifier.verifyProof(
        Authorisation_00.proof.a,
        Authorisation_00.proof.b,
        Authorisation_00.proof.c,
        constructProofVerifierInputs(Authorisation_00, true),
      );
      expect(result, "merkleAuthProofVerifier.verifyProof").to.be.equal(false);
    });
  });

  /* ----------------------- KeyringMerkleAuthZkVerifier ---------------------- */

  describe("KeyringMerkleAuthZkVerifier", function () {
    it("should return true for valid proofs", async function () {
      const birthday = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(Authorisation_00.root as string, birthday);

      const result = await keyringMerkleAuthZkVerifier.checkClaim(Authorisation_00);
      expect(result, "keyringMerkleAuthZkVerifier.checkClaim").to.be.equal(true);
    });

    it("should return false for invalid proofs ", async function () {
      const invalidRoot = "0x1fad8de558447cd0fce868283cee58c9cba2d2a2bb2d210100c29eb5e20b9687";
      const invalidRootProof = {
        ...Authorisation_00,
        root: invalidRoot,
      };
      expect(await keyringMerkleAuthZkVerifier.checkClaim(invalidRootProof), "invalidRoot").to.be.equal(false);

      /* TOOD - refactor
      const invalidProof = membershipProof1.proof;
      const invalidMembershipProof5 = {
        ...membershipProof0,
        proof: invalidProof,
      };
      expect(await keyringZkVerifier.checkClaim(invalidMembershipProof5, authorisationProof0)).to.be.equal(false);

      const invalidAuthorisationProof: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
        ...authorisationProof0,
        tradingAddress: "0x000000000000000000000000b91cf31af85a91c6a4ad507f73f083513f7dcb05",
      };
      expect(
        await keyringZkVerifier.checkClaim(membershipProof0, invalidAuthorisationProof),
        "invalidAddress",
      ).to.be.equal(false);
      */
    });
  });

  /* ------------------ KeyringMerkleAuthZkCredentialUpdater ------------------ */

  describe("KeyringMerkleAuthZkCredentialUpdater", function () {
    it("should only allow the trader itself to update their trader credentials", async function () {
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(Authorisation_00.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await expect(credentialsUpdater.updateCredentials(identityTree.address, Authorisation_00)).to.be.revertedWith(
        unacceptable("only trader can update trader credentials"),
      );
    });

    it("should pack and unpack policy ids", async function () {
      const policyIdArray = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24];
      const packed = await credentialsUpdater.pack12x20(policyIdArray);
      const unpacked = await credentialsUpdater.unpack12x20(packed);
      expect(unpacked).to.have.members(policyIdArray);

      // max value is 2^240 - 1
      const invalidInput = ethers.BigNumber.from("0x1").shl(241).sub(1);
      await expect(credentialsUpdater.unpack12x20(invalidInput)).to.be.revertedWith("input out of range");
      const validInput = ethers.BigNumber.from("0x1").shl(240).sub(1);
      await credentialsUpdater.unpack12x20(validInput);
    });

    it("should allow update credentials with valid proofs of a trader", async function () {
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(Authorisation_00.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00);

      // check if credentials are set properly
      const unpacked1 = await credentialsUpdater.unpack12x20(Authorisation_00.policyDisclosures[0]);
      const unpacked2 = await credentialsUpdater.unpack12x20(Authorisation_00.policyDisclosures[1]);
      // policies: [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0,  0,  0,  0,  0,  0,  0,  0 ]
      const policies = [...unpacked1, ...unpacked2];
      for (let i = 0; i < policies.length; i++) {
        const key = await credentials.keyGen(trader0.address, policies[i]);
        const timestamp = await credentials.subjectUpdates(key);
        // NOTE it should NOT be possible to create a cached credential for admission policies with ID zero
        policies[i] === 0 ? expect(timestamp.toNumber()).to.be.equal(0) : expect(timestamp.toNumber()).to.be.equal(now);
      }
    });

    it("should not allow update credentials with invalid proofs of a trader", async function () {
      const invalidRoot = "0x1fad8de558447cd0fce868283cee58c9cba2d2a2bb2d210100c29eb5e20b9687";
      const invalidRootProof = {
        ...Authorisation_00,
        root: invalidRoot,
      };
      expect(await keyringMerkleAuthZkVerifier.checkClaim(invalidRootProof), "invalidRoot").to.be.equal(false);

      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, invalidRootProof),
      ).to.revertedWith(unacceptable("Proof unacceptable"));
    });

    it("should not allow invalid policies or invalid trees (policy attestors)", async function () {
      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(attacker, Authorisation_00),
      ).to.revertedWith(unacceptable("attestor unacceptable"));

      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00),
      ).to.revertedWith(unacceptable("policy or attestor unacceptable"));

      // add merkle root
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(Authorisation_00.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      // deploy another identity tree which is not allowed to be used by the policy
      const identityTreeFactory = (await ethers.getContractFactory("IdentityTree")) as IdentityTree__factory;
      const forwarder = "0x0000000000000000000000000000000000000001";
      const identityTree2 = await identityTreeFactory.deploy(forwarder, policyManager.address, MAXIMUM_CONSENT_PERIOD);
      await policyManager.admitAttestor(identityTree2.address, "attestor2");

      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree2.address, Authorisation_00),
      ).to.revertedWith(unacceptable("policy or attestor unacceptable"));

      await credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00);
    });
  });

  // TODO - refactor this test so that it can be reused across different CredentialUpdater tests
  describe("Backdoor", function () {
    it("should allow the backdoor admin to admit a backdoor globally and a policy admin to admit and remove a backdoor locally", async function () {
      const admissionPolicyId = 1;

      const role = await policyManager.ROLE_GLOBAL_BACKDOOR_ADMIN();
      expect(await policyManager.hasRole(role, admin)).to.be.true;
      expect(await policyManager.hasRole(role, attacker)).to.be.false;

      await expect(policyManager.connect(attackerAsSigner).admitBackdoor(Authorisation_00.regimeKey)).to.revertedWith(
        "sender does not have the required role",
      );

      expect(await policyManager.callStatic.globalBackdoorCount()).to.be.equal("0");
      expect(await policyManager.callStatic.policyBackdoorCount(admissionPolicyId)).to.be.equal("0");

      await policyManager.admitBackdoor(Authorisation_00.regimeKey);

      expect(await policyManager.callStatic.globalBackdoorCount()).to.be.equal("1");
      expect(await policyManager.callStatic.policyBackdoorCount(admissionPolicyId)).to.be.equal("0");

      const backdoorId = await policyManager.callStatic.globalBackdoorAtIndex(0);
      expect(await policyManager.callStatic.isGlobalBackdoor(backdoorId)).to.be.true;
      const backdoorPubKey = await policyManager.callStatic.backdoorPubKey(backdoorId);
      expect(backdoorPubKey[0]).to.be.equal(Authorisation_00.regimeKey[0]);
      expect(backdoorPubKey[1]).to.be.equal(Authorisation_00.regimeKey[1]);

      let now = await helpers.time.latest();
      let deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      await policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId, deadline);
      await applyPolicyChanges(policyManager, admissionPolicyId);

      expect(await policyManager.callStatic.policyBackdoorCount(admissionPolicyId)).to.be.equal("1");
      expect(await policyManager.callStatic.isPolicyBackdoor(admissionPolicyId, backdoorId)).to.be.true;

      expect(await policyManager.callStatic.policyBackdoorAtIndex(admissionPolicyId, 0)).to.be.equal(backdoorId);

      const policyBackdoors = await policyManager.callStatic.policyBackdoors(admissionPolicyId);
      expect(policyBackdoors[0]).to.be.equal(backdoorId);

      const bogusBackdoorId = "0xb510d6a4349e234dfabbcd6011c946148c07ba27d0f6dd4021901e76c0ca050d";
      await expect(policyManager.addPolicyBackdoor(admissionPolicyId, bogusBackdoorId, 0)).to.be.revertedWith(
        unacceptable("unknown backdoor"),
      );

      await policyManager.removePolicyBackdoor(admissionPolicyId, backdoorId, 0);
      await policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId, 0);

      await expect(policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId, 0)).to.be.revertedWith(
        unacceptable("backdoor exists in policy"),
      );

      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      await policyManager.removePolicyBackdoor(admissionPolicyId, backdoorId, deadline);
      await expect(policyManager.removePolicyBackdoor(admissionPolicyId, backdoorId, 0)).to.be.revertedWith(
        unacceptable("backdoor removal already scheduled"),
      );
      await applyPolicyChanges(policyManager, admissionPolicyId);

      await expect(policyManager.removePolicyBackdoor(admissionPolicyId, backdoorId, 0)).to.be.revertedWith(
        unacceptable("backdoor is not in policy"),
      );

      await policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId, 0);
      await expect(policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId, 0)).to.be.revertedWith(
        unacceptable("backdoor addition already scheduled"),
      );

      await policyManager.removePolicyBackdoor(admissionPolicyId, backdoorId, 0);
    });

    it("should work according to the requirements", async function () {
      let now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(Authorisation_00.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00);

      // admit two backdoors
      await policyManager.admitBackdoor(Authorisation_00.regimeKey);
      const regimeKey2 = [
        "0x04b14ba625d2179ae09013f084b5abccd99614cf0299be43d66c2b20fccd3aef",
        "0x21885b40bc68312206623380b9ff13d30a45225c61a30661bf5dee51882e9bb9",
      ];
      await policyManager.admitBackdoor(regimeKey2 as any);
      const backdoorId1 = await policyManager.callStatic.globalBackdoorAtIndex(0);
      const backdoorId2 = await policyManager.callStatic.globalBackdoorAtIndex(1);

      let deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      const admissionPolicyId = 1;
      const anotherPolicyId = 2;
      await policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId1, deadline);
      await policyManager.addPolicyBackdoor(anotherPolicyId, backdoorId2, deadline);
      await applyPolicyChanges(policyManager, admissionPolicyId);

      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00),
      ).to.revertedWith(unacceptable("all policies in the proof must rely on the same backdoor or no backdoor"));

      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      await policyManager.removePolicyBackdoor(anotherPolicyId, backdoorId2, deadline);
      await policyManager.addPolicyBackdoor(anotherPolicyId, backdoorId1, deadline);
      await applyPolicyChanges(policyManager, anotherPolicyId);
      await credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00);

      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      await expect(policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId2, deadline)).to.revertedWith(
        unacceptable("too many backdoors requested"),
      );

      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      await policyManager.removePolicyBackdoor(admissionPolicyId, backdoorId1, deadline);
      await policyManager.addPolicyBackdoor(admissionPolicyId, backdoorId2, deadline);
      await policyManager.removePolicyBackdoor(anotherPolicyId, backdoorId1, deadline);
      await applyPolicyChanges(policyManager, admissionPolicyId);

      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(identityTree.address, Authorisation_00),
      ).to.revertedWith(unacceptable("Proof does not contain required backdoor regimeKey"));
    });
  });
});
