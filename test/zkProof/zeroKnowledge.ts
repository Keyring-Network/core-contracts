import { BigNumber, BigNumberish, Signer } from "ethers";
import { createFixtureLoader } from "ethereum-waffle";
import { ethers as Ethers } from "ethers";
import { getNamedAccounts, ethers, waffle } from "hardhat";
import { expect } from "chai";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import { keyringTestFixture } from "../shared/fixtures";
import { PolicyStorage } from "../../src/types/PolicyManager";
import type {
  KeyringCredentials,
  PolicyManager,
  KeyringZkCredentialUpdater,
  KeyringZkVerifier,
  WalletCheck,
  IdentityTree,
  IKeyringZkVerifier,
} from "../../src/types";
import {
  namedAccounts,
  authorisationProof,
  constructionProof,
  membershipProof,
  proofMerkleRoot,
  membershipProof2,
  authorisationProof2,
  proofMerkleRoot2,
  trader2,
  ROLE_AGGREGATOR,
  proofMerkleRoot3,
} from "../../constants";
import {
  AuthorizationProofVerifier,
  IdentityConstructionProofVerifier,
  IdentityMembershipProofVerifier,
} from "../../src/typesHardcoded";

/* -------------------------------------------------------------------------- */
/* Test to ensure that Zero Knowledge related contracts are working properly  */
/* -------------------------------------------------------------------------- */

describe("Zero-knowledge", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];

  // prepare contracts with interfaces
  let credentials: KeyringCredentials;
  let policyManager: PolicyManager;
  let credentialsUpdater: KeyringZkCredentialUpdater;
  let keyringZkVerifier: KeyringZkVerifier;
  let walletCheck: WalletCheck;
  let identityTree: IdentityTree;
  let authorizationProofVerifier: AuthorizationProofVerifier;
  let identityMembershipProofVerifier: IdentityMembershipProofVerifier;
  let identityConstructionProofVerifier: IdentityConstructionProofVerifier;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  // policy struct to be used in tests
  let policyScalar: PolicyStorage.PolicyScalarStruct;

  // accounts in this test
  let admin: string;
  let bob: string;
  let attacker: string;
  let attackerAsSigner: Signer;

  before(async () => {
    const { admin: adminAddress, bob: bobAddress, attacker: attackerAddress } = await getNamedAccounts();
    admin = adminAddress;
    bob = bobAddress;
    // `attacker` connect's with contract and try to sign invalid
    attacker = attackerAddress;
    attackerAsSigner = ethers.provider.getSigner(attacker);
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  beforeEach(async function () {
    // load pre-configured contracts
    const fixture = await loadFixture(keyringTestFixture);
    credentials = fixture.contracts.credentials;
    policyManager = fixture.contracts.policyManager;
    credentialsUpdater = fixture.contracts.credentialsUpdater;
    keyringZkVerifier = fixture.contracts.keyringZkVerifier;
    walletCheck = fixture.contracts.walletCheck;
    identityTree = fixture.contracts.identityTree;
    authorizationProofVerifier = fixture.contracts.authorizationProofVerifier;
    identityMembershipProofVerifier = fixture.contracts.identityMembershipProofVerifier;
    identityConstructionProofVerifier = fixture.contracts.identityConstructionProofVerifier;

    policyScalar = fixture.policyScalar;
  });

  /* ------------------------------ IdentityTree ------------------------------ */
  describe("IdentityTree", function () {
    it("should only let admin set merkle root birthday", async function () {
      let merkleRootCount = await identityTree.merkleRootCount();
      expect(merkleRootCount.toNumber()).to.equal(0);

      const birthday = await helpers.time.latest();
      const merkleRoot = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root"));
      expect(await identityTree.isMerkleRoot(merkleRoot)).to.equal(false);

      await expect(
        identityTree.connect(attackerAsSigner).setMerkleRootBirthday(merkleRoot, birthday),
      ).to.be.revertedWith(
        unauthorized(
          attacker,
          "KeyringAccessControl",
          "_checkRole",
          ROLE_AGGREGATOR,
          "sender does not have the required role",
          "IdentityTree::onlyAggregator",
        ),
      );

      await identityTree.setMerkleRootBirthday(merkleRoot, birthday);
      merkleRootCount = await identityTree.merkleRootCount();
      expect(merkleRootCount.toNumber()).to.equal(1);
      expect(await identityTree.isMerkleRoot(merkleRoot)).to.equal(true);
      expect(await identityTree.merkleRootAtIndex(merkleRootCount.toNumber() - 1)).to.equal(merkleRoot);
      expect((await identityTree.merkleRootSuccessors(merkleRoot)).toNumber()).to.equal(0);
    });

    it("should not allow to set birthdays in the future", async function () {
      const birthday = (await helpers.time.latest()) + 1000;
      const merkleRoot = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root"));

      await expect(identityTree.setMerkleRootBirthday(merkleRoot, birthday)).to.be.revertedWith(
        unacceptable("birthday cannot be in the future"),
      );
    });

    it("should calculate merkle root successors correct", async function () {
      let birthday = (await helpers.time.latest()) - 1000;
      const merkleRoot1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root"));

      await identityTree.setMerkleRootBirthday(merkleRoot1, birthday);

      const merkleRoot2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root 2"));
      birthday += 500;
      await identityTree.setMerkleRootBirthday(merkleRoot2, birthday);

      expect((await identityTree.merkleRootSuccessors(merkleRoot1)).toNumber()).to.equal(1);
    });
  });

  /* ----------------------------- KeyringZkVerifier --------------------------- */
  describe("KeyringZkVerifier", function () {
    it("should return true for valid proofs", async function () {
      const birthday = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(proofMerkleRoot, birthday);

      /* --------------------------- Authorisation Proof -------------------------- */
      let result = await authorizationProofVerifier.verifyProof(
        authorisationProof.proof.a,
        authorisationProof.proof.b,
        authorisationProof.proof.c,
        [
          authorisationProof.externalNullifier,
          authorisationProof.nullifierHash,
          authorisationProof.policyDisclosures[0],
          authorisationProof.policyDisclosures[1],
          authorisationProof.tradingAddress,
        ],
      );
      expect(result).to.be.equal(true);

      result = await keyringZkVerifier.checkIdentityAuthorisationProof(authorisationProof);
      expect(result).to.be.equal(true);
      expect(await verifyMembershipProof(identityMembershipProofVerifier, membershipProof)).to.be.equal(true);
      result = await keyringZkVerifier.checkIdentityMembershipProof(membershipProof);
      expect(result).to.be.equal(true);

      /* --------------------------- Construction Proof --------------------------- */
      result = await identityConstructionProofVerifier.verifyProof(
        constructionProof.proof.a,
        constructionProof.proof.b,
        constructionProof.proof.c,
        [constructionProof.identity, constructionProof.policyCommitment, constructionProof.maxAddresses],
      );
      expect(result).to.be.equal(true);

      result = await keyringZkVerifier.checkIdentityConstructionProof(constructionProof);
      expect(result).to.be.equal(true);

      // now check both proofs (membership + authorisation)
      result = await keyringZkVerifier.checkClaim(membershipProof, authorisationProof);
      expect(result).to.be.equal(true);
    });

    it("should return false for invalid proofs ", async function () {
      const invalidExternalNullifier = "0x0000000000000000000000000000000000000000000000000000000000000002";
      const invalidMembershipProof: IKeyringZkVerifier.IdentityMembershipProofStruct = {
        ...membershipProof,
        externalNullifier: invalidExternalNullifier,
      };
      expect(await keyringZkVerifier.checkClaim(invalidMembershipProof, authorisationProof)).to.be.equal(false);

      const invalidNullifierHash = "0x157f1066190cb6fcf0d89ef6ef75c015121ad90ec1a9ceffcbab088d7ec743a1";
      const invalidMembershipProof2 = {
        ...membershipProof,
        nullifierHash: invalidNullifierHash,
      };
      expect(await keyringZkVerifier.checkClaim(invalidMembershipProof2, authorisationProof)).to.be.equal(false);

      const invalidSignalHash = "0x0020463d390a03b6e100c5b7cef5a5ac0808b8afc4643ddbdaf1057c610f2ea2";
      const invalidMembershipProof3 = {
        ...membershipProof,
        signalHash: invalidSignalHash,
      };
      expect(await keyringZkVerifier.checkClaim(invalidMembershipProof3, authorisationProof)).to.be.equal(false);

      const invalidRoot = "0x1fad8de558447cd0fce868283cee58c9cba2d2a2bb2d210100c29eb5e20b9687";
      const invalidMembershipProof4 = {
        ...membershipProof,
        root: invalidRoot,
      };
      expect(await keyringZkVerifier.checkClaim(invalidMembershipProof4, authorisationProof)).to.be.equal(false);

      const invalidProof = membershipProof2.proof;
      const invalidMembershipProof5 = {
        ...membershipProof,
        proof: invalidProof,
      };
      expect(await keyringZkVerifier.checkClaim(invalidMembershipProof5, authorisationProof)).to.be.equal(false);

      const invalidAuthorisationProof: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
        ...authorisationProof,
        tradingAddress: bob,
      };
      expect(await keyringZkVerifier.checkClaim(membershipProof, invalidAuthorisationProof)).to.be.equal(false);

      const proofMaxAddresses = Ethers.BigNumber.from(constructionProof.maxAddresses);

      const invalidPolicyCommitment = "0x28a907f8ab71f2626449579031ed7d886cd6a9f64d3472832c9faba87eb1a06c";
      const invalidConstructionProof: IKeyringZkVerifier.IdentityConstructionProofStruct = {
        ...constructionProof,
        policyCommitment: invalidPolicyCommitment,
      };
      expect(await keyringZkVerifier.checkIdentityConstructionProof(invalidConstructionProof)).to.be.equal(false);
    });
  });

  /* ----------------------- KeyringZkCredentialUpdater ----------------------- */

  describe("KeyringZkCredentialUpdater", function () {
    it("should pack and unpack policy ids", async function () {
      const policyIdArray = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24];
      const packed = await credentialsUpdater.pack12x20(policyIdArray);
      const unpacked = await credentialsUpdater.unpack12x20(packed);
      expect(unpacked).to.have.members(policyIdArray);
    });

    it("should allow update credentials with valid proofs of a trader", async function () {
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(proofMerkleRoot2, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);

      // check if credentials are set properly
      const version = 1;
      const unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[0]);
      const unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[1]);
      // policies: [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0,  0,  0,  0,  0,  0,  0,  0 ]
      const policies = [...unpacked1, ...unpacked2];
      for (let i = 0; i < policies.length; i++) {
        const timestamp = await credentials.getCredential(version, trader2.address, policies[i]);
        // NOTE it should NOT be possible to create a cached credential for admission policies with ID zero
        policies[i] === 0 ? expect(timestamp.toNumber()).to.be.equal(0) : expect(timestamp.toNumber()).to.be.equal(now);
      }
    });

    it("should allow only policy admin to tear down credentials", async function () {
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(proofMerkleRoot2, now);

      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);
      const version = 1;
      const unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[0]);
      const unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[1]);
      const policies = [...unpacked1, ...unpacked2];
      const index = 5;
    });

    it("should not allow update credentials with invalid proofs of a trader", async function () {
      const invalidAuthorisationProof: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
        ...authorisationProof2,
        tradingAddress: bob,
      };
      await expect(
        credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, invalidAuthorisationProof),
      ).to.revertedWith(unacceptable("Proof unacceptable"));
    });

    it("should not allow invalid policies or invalid trees (policy attestors)", async function () {
      await expect(
        credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2),
      ).to.revertedWith(unacceptable("policy or attestor unacceptable"));

      // add merkle root
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(proofMerkleRoot2, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      // deploy another identity tree which is not allowed to be used by the policy
      const identityTreeFactory = await ethers.getContractFactory("IdentityTree");
      const forwarder =  "0x0000000000000000000000000000000000000001"
      const identityTree2 = await identityTreeFactory.deploy(forwarder);
      await policyManager.admitAttestor(identityTree2.address, "attestor2");

      await expect(
        credentialsUpdater.updateCredentials(identityTree2.address, membershipProof2, authorisationProof2),
      ).to.revertedWith(unacceptable("policy or attestor unacceptable"));

      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);
    });

    it("should allow extend validity of credentials to forever in case of attestor failure", async function () {
      // user with valid proofs and get valid credentials even if the timestamp comming from the latest root are stale
      // if acceptRoot property is set on the policy by the policy admin

      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(proofMerkleRoot2, now);

      const policyScalarEvenNumbers = {
        ...policyScalar,
        acceptRoots: 0,
      };

      // current policy count 2, create policyId 2 to 21
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        const index = i + 2; // policyId starts from 2
        if (index % 2 === 0) {
          // create even policies
          await policyManager.createPolicy(policyScalarEvenNumbers, [identityTree.address], [walletCheck.address]);
        } else {
          // create odd policies
          await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
        }
      }

      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);

      // check if credentials are set properly
      const version = 1;
      const unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[0]);
      const unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof2.policyDisclosures[1]);
      // e.g. policies: [ 1,  2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15, 16, 0,  0,  0,  0,  0,  0,  0,  0 ]
      const policies = [...unpacked1, ...unpacked2];
      // check for valid credentials
      for (let i = 0; i < policies.length; i++) {
        const timestamp = await credentials.getCredential(version, trader2.address, policies[i]);
        if (policies[i] === 0) {
          expect(timestamp.toNumber()).to.be.equal(0);
        } else {
          expect(timestamp.toNumber()).to.be.equal(now);
          expect(await isCompliant(timestamp, policyScalar.ttl)).to.be.true;
        }
      }

      const staleTime = BigNumber.from(policyScalar.ttl).add(100);
      await helpers.time.increase(staleTime);

      // check for stale credentials
      for (let i = 0; i < policies.length; i++) {
        const timestamp = await credentials.getCredential(version, trader2.address, policies[i]);
        if (policies[i] === 0) {
          expect(timestamp.toNumber()).to.be.equal(0);
        } else {
          expect(timestamp.toNumber()).to.be.equal(now);
          expect(await isCompliant(timestamp, policyScalar.ttl)).to.be.false;
        }
      }

      // update credentials with old merkle root
      await credentialsUpdater.updateCredentials(identityTree.address, membershipProof2, authorisationProof2);

     // check for updated credentials without new merkle root
      for (let i = 0; i < policies.length; i++) {
        if (policies[i] === 0 || policies[i] === 1) continue;
        // set the merkleRootSuccessors to 1, after 10 policies
        if (i === 10) await identityTree.setMerkleRootBirthday(proofMerkleRoot3, now);
        const timestamp = await credentials.getCredential(version, trader2.address, policies[i]);
        const acceptRoots = await policyManager.callStatic.policyAcceptRoots(policies[i]);
        if (policies[i] % 2 === 0) {
          // even policies greater from 2 should be invalid (acceptRoots: 0)
          expect(await isCompliant(timestamp, policyScalar.ttl)).to.be.false;
          expect(acceptRoots).to.be.equal(0);
        } else {
          // odd policies greater from 2 should be valid (acceptRoots: 1)
          expect(await isCompliant(timestamp, policyScalar.ttl)).to.be.true;
          expect(acceptRoots).to.be.equal(1);
        }
      }
    });
  });

  /* --------------------------- KeyringCredentials --------------------------- */
  describe("KeyringCredentials", function () {
    it("should not allow set credentials with timestamp in the future", async function () {
      const future = (await helpers.time.latest()) + 1000;
      await credentials.grantRole(await credentials.ROLE_CREDENTIAL_UPDATER(), admin);
      await expect(credentials.setCredential(admin, 0, future)).to.revertedWith(
        unacceptable("timestamp must be in the past"),
      );
    });
    it("should not allow unauthorized entities to set credentials", async function () {
      const now = await helpers.time.latest();
      const admissionPolicyId = 0;
      const role = await credentials.ROLE_CREDENTIAL_UPDATER();

      await expect(credentials.connect(attackerAsSigner).grantRole(role, attacker)).to.revertedWith(
        "missing role 0x0000000000000000000000000000000000000000000000000000000000000000",
      );

      await expect(
        credentials.connect(attackerAsSigner).setCredential(attacker, admissionPolicyId, now),
      ).to.revertedWith(
        unauthorized(
          attacker,
          "KeyringAccessControl",
          "_checkRole",
          role,
          "sender does not have the required role",
          "KeyringCredentials:onlyUpdater",
        ),
      );
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

const unacceptable = (reason: string) => {
  return `Unacceptable("${reason}")`;
};

const unauthorized = (
  sender: string,
  module: string,
  method: string,
  role: string,
  reason: string,
  context: string,
) => {
  return `Unauthorized("${sender}", "${module}", "${method}", "${role}", "${reason}", "${context}")`;
};

/* ---------------------------- Membership Proof ---------------------------- */
// verifyProof does not return anything. Helper function returns false if verifyProof reverts

const verifyMembershipProof = async (
  identityMembershipProofVerifier: IdentityMembershipProofVerifier,
  struct: IKeyringZkVerifier.IdentityMembershipProofStruct,
) => {
  try {
    await identityMembershipProofVerifier.verifyProof(struct.proof.a, struct.proof.b, struct.proof.c, [
      struct.root,
      struct.nullifierHash,
      struct.signalHash,
      struct.externalNullifier,
    ]);
    return true;
  } catch {
    return false;
  }
};

const isCompliant = async (timestamp: BigNumberish, ttl: BigNumberish) => {
  const now = BigNumber.from(await helpers.time.latest());
  const cacheAge = now.sub(timestamp);
  const isIndeed = cacheAge.lte(ttl);
  return isIndeed;
};
