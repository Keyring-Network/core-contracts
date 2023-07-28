import { Signer, Wallet } from "ethers";
import { createFixtureLoader } from "ethereum-waffle";
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
  AuthorizationVerifier,
  ConstructionVerifier,
  MembershipVerifier20,
  IdentityTree__factory,
} from "../../src/types";
import {
  authorisationProof0,
  constructionProof0,
  MAXIMUM_CONSENT_PERIOD,
  membershipProof0,
  membershipProof1,
  namedAccounts,
  NULL_BYTES32,
  ROLE_AGGREGATOR,
  THIRTY_DAYS_IN_SECONDS,
  trader0,
  trader1,
} from "../constants";

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
  let identityConstructionProofVerifier: ConstructionVerifier;
  let authorizationProofVerifier: AuthorizationVerifier;
  let identityMembershipProofVerifier: MembershipVerifier20;

  // fixture loader
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  // policy struct to be used in tests
  let policyScalar: PolicyStorage.PolicyScalarStruct;

  // accounts in this test
  let admin: string;
  let traderAsSigner0: Signer;
  let attacker: string;
  let attackerAsSigner: Signer;

  before(async () => {
    const { admin: adminAddress, attacker: attackerAddress } = await getNamedAccounts();
    admin = adminAddress;
    // `attacker` connect's with contract and try to sign invalid
    attacker = attackerAddress;
    attackerAsSigner = ethers.provider.getSigner(attacker);
    // set up trader wallets with 2000 ETH each
    traderAsSigner0 = new Wallet(trader0.priv, provider);
    await adminWallet.sendTransaction({ to: trader0.address, value: ethers.utils.parseEther("2000") });
    await adminWallet.sendTransaction({ to: trader1.address, value: ethers.utils.parseEther("2000") });
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
      const admissionPolicyId = 1;
      expect(await identityTree.callStatic.checkRoot(admin, merkleRoot, admissionPolicyId)).to.be.true;
      merkleRootCount = await identityTree.merkleRootCount();
      expect(merkleRootCount.toNumber()).to.equal(1);
      expect(await identityTree.isMerkleRoot(merkleRoot)).to.equal(true);
      expect(await identityTree.merkleRootAtIndex(merkleRootCount.toNumber() - 1)).to.equal(merkleRoot);
      // expect((await identityTree.merkleRootSuccessors(merkleRoot)).toNumber()).to.equal(0);
    });

    it("should not allow to set invalid merkle roots", async function () {
      const validBirthday = await helpers.time.latest();
      let invalidBirthday = validBirthday + 1000;
      const merkleRoot = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root"));

      await expect(identityTree.setMerkleRootBirthday(merkleRoot, invalidBirthday)).to.be.revertedWith(
        unacceptable("birthday cannot be in the future"),
      );

      await expect(identityTree.setMerkleRootBirthday(NULL_BYTES32, validBirthday)).to.be.revertedWith(
        unacceptable("merkle root cannot be empty"),
      );

      await identityTree.setMerkleRootBirthday(merkleRoot, validBirthday);
      invalidBirthday = validBirthday - 1000;
      await expect(identityTree.setMerkleRootBirthday(merkleRoot, invalidBirthday)).to.be.revertedWith(
        unacceptable("birthday precedes previously recorded birthday"),
      );
    });

    it("should not allow access merkle roots out of bounds", async function () {
      const validBirthday = await helpers.time.latest();
      const merkleRoot1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root"));
      await identityTree.setMerkleRootBirthday(merkleRoot1, validBirthday);
      const merkleRootCount = await identityTree.merkleRootCount();
      await expect(identityTree.merkleRootAtIndex(merkleRootCount)).to.be.revertedWith("index");
      expect(await identityTree.merkleRootAtIndex(merkleRootCount.toNumber() - 1)).to.equal(merkleRoot1);
    });

    it("should provide the latest root stored", async function () {
      expect(await identityTree.latestRoot()).to.equal(NULL_BYTES32);

      const birthday1 = await helpers.time.latest();
      const merkleRoot1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root"));
      await identityTree.setMerkleRootBirthday(merkleRoot1, birthday1);
      expect(await identityTree.latestRoot()).to.equal(merkleRoot1);

      const birthday2 = await helpers.time.latest();
      const merkleRoot2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("some merkle root 2"));
      await identityTree.setMerkleRootBirthday(merkleRoot2, birthday2);
      expect(await identityTree.latestRoot()).to.equal(merkleRoot2);
    });
  });

  describe("AuthorisationVerifier", function () {
    it("should return true for valid proofs", async function () {
      const inputs = flatten_struct(Object.assign({}, authorisationProof0, { proof: undefined })).slice(1) as string[];

      const result = await authorizationProofVerifier.verifyProof(
        authorisationProof0.proof.a,
        authorisationProof0.proof.b,
        authorisationProof0.proof.c,
        inputs,
      );
      expect(result, "authorisationVerifier.verifyProof").to.be.equal(true);
    });

    it("should return false for invalid proofs", async function () {
      const inputs = flatten_struct(Object.assign({}, authorisationProof0, { proof: undefined })).slice(1) as string[];
      inputs[1] = "0x".padEnd(64, "0");

      const result = await authorizationProofVerifier.verifyProof(
        authorisationProof0.proof.a,
        authorisationProof0.proof.b,
        authorisationProof0.proof.c,
        inputs,
      );
      expect(result, "authorisationVerifier.verifyProof").to.be.equal(false);
    });
  });

  describe("MembershipVerifier", function () {
    it("should return true for valid proofs", async function () {
      const inputs = flatten_struct(Object.assign({}, membershipProof0, { proof: undefined })).slice(1) as string[];

      const result = await identityMembershipProofVerifier.verifyProof(
        membershipProof0.proof.a,
        membershipProof0.proof.b,
        membershipProof0.proof.c,
        inputs,
      );
      expect(result, "membershipVerifier.verifyProof").to.be.equal(true);
    });

    it("should return false for invalid proofs", async function () {
      const inputs = flatten_struct(Object.assign({}, membershipProof0, { proof: undefined })).slice(1) as string[];
      inputs[0] = "0x".padEnd(64, "0");

      const result = await identityMembershipProofVerifier.verifyProof(
        membershipProof0.proof.a,
        membershipProof0.proof.b,
        membershipProof0.proof.c,
        inputs,
      );
      expect(result, "membershipVerifier.verifyProof").to.be.equal(false);
    });
  });

  describe("ConstructionVerifier", function () {
    it("should return true for valid proofs", async function () {
      const inputs = flatten_struct(Object.assign({}, constructionProof0, { proof: undefined })).slice(1) as string[];

      let result = await identityConstructionProofVerifier.verifyProof(
        constructionProof0.proof.a,
        constructionProof0.proof.b,
        constructionProof0.proof.c,
        inputs,
      );
      expect(result, "constructionVerifier.verifyProof").to.be.equal(true);

      result = await keyringZkVerifier.checkIdentityConstructionProof({
        proof: {
          a: constructionProof0.proof.a,
          b: constructionProof0.proof.b,
          c: constructionProof0.proof.c,
        },
        inputs,
      });
      expect(result, "constructionVerifier.verifyProof").to.be.equal(true);
    });

    it("should return false for invalid proofs", async function () {
      const inputs = flatten_struct(Object.assign({}, constructionProof0, { proof: undefined })).slice(1) as string[];
      inputs[0] = "0x".padEnd(64, "0");

      const result = await identityConstructionProofVerifier.verifyProof(
        constructionProof0.proof.a,
        constructionProof0.proof.b,
        constructionProof0.proof.c,
        inputs,
      );
      expect(result, "constructionVerifier.verifyProof").to.be.equal(false);
    });
  });

  /* ----------------------------- KeyringZkVerifier --------------------------- */

  describe("KeyringZkVerifier", function () {
    it("should return true for valid proofs", async function () {
      const birthday = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(membershipProof0.root as string, birthday);

      const result = await keyringZkVerifier.checkClaim(membershipProof0, authorisationProof0);
      expect(result, "keyringZkVerifier.checkClaim").to.be.equal(true);
    });

    it("should return false for invalid proofs ", async function () {
      const invalidExternalNullifier = "0x0000000000000000000000000000000000000000000000000000000000000002";
      const invalidMembershipProof: IKeyringZkVerifier.IdentityMembershipProofStruct = {
        ...membershipProof0,
        externalNullifier: invalidExternalNullifier,
      };
      expect(
        await keyringZkVerifier.checkClaim(invalidMembershipProof, authorisationProof0),
        "invalidExternalNullifier",
      ).to.be.equal(false);

      const invalidNullifierHash = "0x157f1066190cb6fcf0d89ef6ef75c015121ad90ec1a9ceffcbab088d7ec743a1";
      const invalidMembershipProof2 = {
        ...membershipProof0,
        nullifierHash: invalidNullifierHash,
      };
      expect(
        await keyringZkVerifier.checkClaim(invalidMembershipProof2, authorisationProof0),
        "invalidNullifierHash",
      ).to.be.equal(false);

      const invalidSignalHash = "0x0020463d390a03b6e100c5b7cef5a5ac0808b8afc4643ddbdaf1057c610f2ea2";
      const invalidMembershipProof3 = {
        ...membershipProof0,
        signalHash: invalidSignalHash,
      };
      expect(
        await keyringZkVerifier.checkClaim(invalidMembershipProof3, authorisationProof0),
        "invalidSignalHash",
      ).to.be.equal(false);

      const invalidRoot = "0x1fad8de558447cd0fce868283cee58c9cba2d2a2bb2d210100c29eb5e20b9687";
      const invalidMembershipProof4 = {
        ...membershipProof0,
        root: invalidRoot,
      };
      expect(
        await keyringZkVerifier.checkClaim(invalidMembershipProof4, authorisationProof0),
        "invalidRoot",
      ).to.be.equal(false);

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
    });
  });

  /* ----------------------- KeyringZkCredentialUpdater ----------------------- */

  describe("KeyringZkCredentialUpdater", function () {
    it("should only allow the trader itself to update their trader credentials", async function () {
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(membershipProof0.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await expect(
        credentialsUpdater.updateCredentials(identityTree.address, membershipProof0, authorisationProof0),
      ).to.be.revertedWith(unacceptable("only trader can update trader credentials"));
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
      await identityTree.setMerkleRootBirthday(membershipProof0.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await credentialsUpdater
        .connect(traderAsSigner0)
        .updateCredentials(identityTree.address, membershipProof0, authorisationProof0);

      // check if credentials are set properly
      const unpacked1 = await credentialsUpdater.unpack12x20(authorisationProof0.policyDisclosures[0]);
      const unpacked2 = await credentialsUpdater.unpack12x20(authorisationProof0.policyDisclosures[1]);
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
      const invalidAuthorisationProof: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
        ...authorisationProof0,
        proof: membershipProof1.proof,
      };

      expect(
        await keyringZkVerifier.checkClaim(membershipProof0, invalidAuthorisationProof),
        "invalidAddress",
      ).to.be.equal(false);

      await expect(
        credentialsUpdater
          .connect(traderAsSigner0)
          .updateCredentials(identityTree.address, membershipProof0, invalidAuthorisationProof),
      ).to.revertedWith(unacceptable("Proof unacceptable"));
    });

    it("should not allow invalid policies or invalid trees (policy attestors)", async function () {
      await expect(
        credentialsUpdater.connect(traderAsSigner0).updateCredentials(attacker, membershipProof0, authorisationProof0),
      ).to.revertedWith(unacceptable("attestor unacceptable"));

      await expect(
        credentialsUpdater
          .connect(traderAsSigner0)
          .updateCredentials(identityTree.address, membershipProof0, authorisationProof0),
      ).to.revertedWith(unacceptable("policy or attestor unacceptable"));

      // add merkle root
      const now = await helpers.time.latest();
      await identityTree.setMerkleRootBirthday(membershipProof0.root as string, now);

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
        credentialsUpdater
          .connect(traderAsSigner0)
          .updateCredentials(identityTree2.address, membershipProof0, authorisationProof0),
      ).to.revertedWith(unacceptable("policy or attestor unacceptable"));

      await credentialsUpdater
        .connect(traderAsSigner0)
        .updateCredentials(identityTree.address, membershipProof0, authorisationProof0);
    });
  });

  /* --------------------------- KeyringCredentials --------------------------- */

  describe("KeyringCredentials", function () {
    it("should not allow set credentials with invalid timestamp", async function () {
      const future = (await helpers.time.latest()) + 1000;
      await credentials.grantRole(await credentials.ROLE_CREDENTIAL_UPDATER(), admin);
      await expect(credentials.setCredential(admin, 0, future)).to.revertedWith(
        unacceptable("time must be in the past"),
      );

      const validTimestamp = await helpers.time.latest();
      const admissionPolicyId = 1;
      await credentials.setCredential(admin, admissionPolicyId, validTimestamp);
      const key = await credentials.keyGen(admin, admissionPolicyId);
      const timestamp = await credentials.subjectUpdates(key);
      expect(timestamp).to.be.equal(validTimestamp);
      const invalidTimestamp = validTimestamp - 1000;
      await expect(credentials.setCredential(admin, admissionPolicyId, invalidTimestamp)).to.revertedWith(
        unacceptable("time is older than existing update"),
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

  /* ------------------------------ Backdoor -------------------------------- */

  describe("Backdoor", function () {
    it("should allow the backdoor admin to admit a backdoor globally and a policy admin to admit and remove a backdoor locally", async function () {
      const admissionPolicyId = 1;

      const role = await policyManager.ROLE_GLOBAL_BACKDOOR_ADMIN();
      expect(await policyManager.hasRole(role, admin)).to.be.true;
      expect(await policyManager.hasRole(role, attacker)).to.be.false;

      await expect(
        policyManager.connect(attackerAsSigner).admitBackdoor(authorisationProof0.regimeKey),
      ).to.revertedWith("sender does not have the required role");

      expect(await policyManager.callStatic.globalBackdoorCount()).to.be.equal("0");
      expect(await policyManager.callStatic.policyBackdoorCount(admissionPolicyId)).to.be.equal("0");

      await policyManager.admitBackdoor(authorisationProof0.regimeKey);

      expect(await policyManager.callStatic.globalBackdoorCount()).to.be.equal("1");
      expect(await policyManager.callStatic.policyBackdoorCount(admissionPolicyId)).to.be.equal("0");

      const backdoorId = await policyManager.callStatic.globalBackdoorAtIndex(0);
      expect(await policyManager.callStatic.isGlobalBackdoor(backdoorId)).to.be.true;
      const backdoorPubKey = await policyManager.callStatic.backdoorPubKey(backdoorId);
      expect(backdoorPubKey[0]).to.be.equal(authorisationProof0.regimeKey[0]);
      expect(backdoorPubKey[1]).to.be.equal(authorisationProof0.regimeKey[1]);

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
      await identityTree.setMerkleRootBirthday(membershipProof0.root as string, now);

      // create 20 policies
      const numberOfPolices = 20;
      for (let i = 0; i < numberOfPolices; i++) {
        await policyManager.createPolicy(policyScalar, [identityTree.address], [walletCheck.address]);
      }

      await credentialsUpdater
        .connect(traderAsSigner0)
        .updateCredentials(identityTree.address, membershipProof0, authorisationProof0);

      // admit two backdoors
      await policyManager.admitBackdoor(authorisationProof0.regimeKey);
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
        credentialsUpdater
          .connect(traderAsSigner0)
          .updateCredentials(identityTree.address, membershipProof0, authorisationProof0),
      ).to.revertedWith(unacceptable("all policies in the proof must rely on the same backdoor or no backdoor"));

      now = await helpers.time.latest();
      deadline = now + THIRTY_DAYS_IN_SECONDS + 100;
      await policyManager.removePolicyBackdoor(anotherPolicyId, backdoorId2, deadline);
      await policyManager.addPolicyBackdoor(anotherPolicyId, backdoorId1, deadline);
      await applyPolicyChanges(policyManager, anotherPolicyId);
      await credentialsUpdater
        .connect(traderAsSigner0)
        .updateCredentials(identityTree.address, membershipProof0, authorisationProof0);

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
        credentialsUpdater
          .connect(traderAsSigner0)
          .updateCredentials(identityTree.address, membershipProof0, authorisationProof0),
      ).to.revertedWith(unacceptable("Proof does not contain required backdoor regimeKey"));
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

const applyPolicyChanges = async (policyManager: PolicyManager, policyId: number) => {
  const policyObj = await policyManager.callStatic.policy(policyId);
  await helpers.time.increaseTo(policyObj.deadline.toNumber());
  await policyManager.policy(policyId);
};
