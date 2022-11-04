import { getNamedAccounts, ethers, waffle } from "hardhat";
import { createFixtureLoader } from "ethereum-waffle";
import { expect } from "chai";

import type { KeyringCredentials, RuleRegistry, PolicyManager, KeyringV1CredentialUpdater } from "../../src/types";
import { namedAccounts, Operator, baseRules } from "../../constants";
import { Attestation, SignedAttestation, signAttestation } from "../eip712/signUtil";
import { keyringTestFixture } from "../shared/fixtures";

const ONE_DAY_IN_SECONDS = 24 * 60 * 60;
const DEFAULT_GRACE_TIME = 600;

/* -------------------------------------------------------------------------- */
/*         Test to ensure that credentials can be updated and rejected.       */
/* -------------------------------------------------------------------------- */

describe("Cryptography", function () {
  // wallets used in this test
  const provider = waffle.provider;
  const wallets = provider.getWallets();
  const adminWallet = wallets[namedAccounts["admin"]];
  const aliceWallet = wallets[namedAccounts["alice"]];
  const verifier1Wallet = wallets[namedAccounts["verifier1"]];

  // prepare contracts with interfaces
  let credentials: KeyringCredentials;
  let ruleRegistry: RuleRegistry;
  let policyManager: PolicyManager;
  let credentialsUpdater: KeyringV1CredentialUpdater;
  let loadFixture: ReturnType<typeof createFixtureLoader>;

  before(async function () {
    // accounts used in this test
    const { admin, alice, verifier1, verifier2 } = await getNamedAccounts();
    this.admin = admin;
    this.alice = alice;
    this.verifier1 = verifier1;
    this.verifier2 = verifier2;
    // pre-configure contracts (see /test/shared/fixtures.ts)
    loadFixture = createFixtureLoader([adminWallet], provider);
  });

  describe("Credentials updates", function () {
    beforeEach(async function () {
      // load pre-configured contracts
      const fixture = await loadFixture(keyringTestFixture);
      credentials = fixture.credentials;
      ruleRegistry = fixture.ruleRegistry;
      policyManager = fixture.policyManager;
      credentialsUpdater = fixture.credentialsUpdater;

      // creating six rules, three base rules and three expression rules (complement, union, intersection)
      // start by creating three base rules and retrieve ruleId's
      await ruleRegistry.createRule(...baseRules.PP_GB);
      await ruleRegistry.createRule(...baseRules.PP_US);
      await ruleRegistry.createRule(...baseRules.PEP);
      const RULE_ID_PP_GB = await ruleRegistry.ruleAtIndex(0);
      const RULE_ID_PP_US = await ruleRegistry.ruleAtIndex(1);
      const RULE_ID_PEP = await ruleRegistry.ruleAtIndex(2);

      // sorting ruleId's in acending order as required
      let sortedRules = sortAscendingOrder([RULE_ID_PP_GB, RULE_ID_PP_US]);

      // create two expression rules and retrieve ruleId's
      await ruleRegistry.createRule("", "", Operator.complement, [RULE_ID_PEP]);
      await ruleRegistry.createRule("", "", Operator.union, sortedRules);
      const RULE_ID_UNION_GB_US = await ruleRegistry.ruleAtIndex(3);
      const RULE_ID_COMPLEMENT_PEP = await ruleRegistry.ruleAtIndex(4);

      // create another expression rule based on the previous two rules
      sortedRules = sortAscendingOrder([RULE_ID_UNION_GB_US, RULE_ID_COMPLEMENT_PEP]);
      await ruleRegistry.createRule("", "", Operator.intersection, sortedRules);
      const RULE_ID_GBUS_EXCL_PEP = await ruleRegistry.ruleAtIndex(5);

      // admit verifiers to the global whitelist
      await policyManager.admitVerifier(this.verifier1, "https://one.verifier");
      await policyManager.admitVerifier(this.verifier2, "https://changeme.verifier");

      await policyManager.updateVerifierUri(this.verifier2, "https://two.verifier");

      // create a first policy
      await policyManager.createPolicy(
        "Intersection: Union [ GB, US ], Complement [ PEP ], 0 of 0",
        RULE_ID_GBUS_EXCL_PEP,
        ONE_DAY_IN_SECONDS,
      );
      const policyId = await policyManager.policyAtIndex(0);
      // setup a quorum of 1 out of 2 required verifiers
      // add two verifiers to the policy
      await policyManager.addPolicyVerifiers(policyId, [this.verifier1, this.verifier2]);
      // set requiredVerifiers to one
      await policyManager.updatePolicy(
        policyId,
        "Intersection: Union [ GB, US ], Complement [ PEP ], 1 of 2",
        RULE_ID_GBUS_EXCL_PEP,
        1,
        ONE_DAY_IN_SECONDS,
      );
      // set Alice's policy to the first one
      await policyManager.connect(aliceWallet).setUserPolicy(policyId);
    });

    it("should be ready to test", async function () {
      expect(true).to.equal(true);
    });

    /**
     * Assemble a message, sign it, and ask the contract who signed it using only the messageHash and signature.
     */

    it("should recover the signer from a signed, typed Attestion request", async function () {
      // first, gather info for the message to sign
      const user = aliceWallet.address;
      const userPolicyId = await policyManager.policyAtIndex(0);
      const admissionPolicyId = await policyManager.policyAtIndex(0);
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      // the message is an instance of the Attestation type
      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        // true indicates this is a request for VERIFIER signer to provide an assessment
        isRequest: true,
      };

      // chain and verifier are part of the EIP712 typedData to sign
      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      // signUtil returns a signedAttestion from the message, chain and receiverAddress, using the wallet with private key to generate the signature.
      // this object can be passed to other users, off-chain.

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        aliceWallet,
      );

      // an off-chain recipient of the signedAttestation can recover the signer by passing the contents to the contract.
      // EIP712 signer recovery can also be performed off-chain. See keyringEIP712.ts for a pure ts method.
      // A VERIFIER Signer should check that the userId in the message matches the recovered address which proves the signer owns the address in the request.

      const recoveredSigner = await credentialsUpdater.getSignerFromSig(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        signedAttestation.message.timestamp,
        signedAttestation.message.isRequest,
        signedAttestation.signature,
      );

      // the recovered address should match the wallet that was used to sign
      expect(recoveredSigner).to.equal(aliceWallet.address);
    });

    it("should recover the verifier from a signed, typed attestation", async function () {
      // first, gather info for the message to sign
      const user = aliceWallet.address;
      const userPolicyId = await policyManager.policyAtIndex(0);
      const admissionPolicyId = await policyManager.policyAtIndex(0);
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      // the message is an instance of the Attestation type
      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        // false indicates this is a response from a VERIFIER signer that has responded in the affirmative.
        isRequest: false,
      };

      // chain and verifier are part of the EIP712 typedData to sign
      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      // signUtil returns a signedAttestion from the message, chain and receiverAddress, using the wallet with private key to generate the signature.
      // this object can be passed to other users, off-chain.

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );

      // an off-chain recipient of the signedAttestation can recover the signer by passing the contents to the contract.
      // EIP712 signer recovery can also be performed off-chain. See keyringEIP712.ts for a pure ts method.
      // the CredentialsUpdater contract will see that this attestation is *about Alice* and check that the signer is on the policy VERIFIER signers list.

      const recoveredSigner = await credentialsUpdater.getSignerFromSig(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        signedAttestation.message.timestamp,
        signedAttestation.message.isRequest,
        signedAttestation.signature,
      );

      // the recovered address should match the wallet that was used to sign
      expect(recoveredSigner).to.equal(verifier1Wallet.address);
    });

    it("should update the credentials", async function () {
      // first, gather info for the message to sign
      const user = aliceWallet.address;
      const userPolicyId = await policyManager.policyAtIndex(0);
      const admissionPolicyId = await policyManager.policyAtIndex(0);
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      // the message is an instance of the Attestation type
      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        // false indicates this is a response from a VERIFIER signer that has responded in the affirmative.
        isRequest: false,
      };

      // chain and verifier are part of the EIP712 typedData to sign
      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      // signUtil returns a signedAttestion from the message, chain and receiverAddress, using the wallet with private key to generate the signature.
      // this object contains the information needed to successfully update the credentials.

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );

      const signatures = [signedAttestation.signature];

      const tx = await credentialsUpdater.updateCredential(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        timestamp,
        signatures,
      );
      await tx.wait();

      const credentialsTime = await credentials.getCredentialV1(
        1,
        user,
        userPolicyId,
        admissionPolicyId);
      expect(credentialsTime.toNumber()).to.equal(timestamp);
    });


    it("should update the credentials for default user policy", async function () {
      // first, gather info for the message to sign
      const user = adminWallet.address;
      const userPolicyId = await policyManager.userPolicy(adminWallet.address);
      ethers.constants.HashZero;
      const admissionPolicyId = await policyManager.policyAtIndex(0);
      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      // user that has not set a policy should have the default user policy id
      expect(userPolicyId).to.be.equal(ethers.constants.HashZero);

      // the message is an instance of the Attestation type
      const attestation: Attestation = {
        user: user,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        // false indicates this is a response from a VERIFIER signer that has responded in the affirmative.
        isRequest: false,
      };

      // chain and verifier are part of the EIP712 typedData to sign
      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      // signUtil returns a signedAttestion from the message, chain and receiverAddress, using the wallet with private key to generate the signature.
      // this object contains the information needed to successfully update the credentials.

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );

      const signatures = [signedAttestation.signature];

      const tx = await credentialsUpdater.updateCredential(
        signedAttestation.message.user,
        signedAttestation.message.userPolicyId,
        signedAttestation.message.admissionPolicyId,
        timestamp,
        signatures,
      );
      await tx.wait();

      const credentialsTime = await credentials.getCredentialV1(
        1,
        user,
        userPolicyId,
        admissionPolicyId);
      expect(credentialsTime.toNumber()).to.equal(timestamp);
    });

    it("should reject invalid inputs in updateCredential", async function () {
      const user = this.alice;
      const userPolicyId = await policyManager.policyAtIndex(0);
      const admissionPolicyId = await policyManager.policyAtIndex(0);

      const blockInfo = await waffle.provider.getBlock("latest");
      const timestamp = blockInfo.timestamp;

      let invalidParameters: [string, string, string, number, Array<string>];

      invalidParameters = [user, userPolicyId, admissionPolicyId, timestamp, []];
      await expect(credentialsUpdater.updateCredential(...invalidParameters)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "updateCredential",
          "insufficient signatures to update Credential"
        )
      );

      const attestation: Attestation = {
        user: this.alice,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        // true indicates this is a resquest from a user
        isRequest: true,
      };

      const { chainId } = await provider.getNetwork();
      const verifyingContract = credentialsUpdater.address;

      const signedAttestation: SignedAttestation = await signAttestation(
        attestation,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );
      invalidParameters = [user, userPolicyId, admissionPolicyId, timestamp, [signedAttestation.signature]];

      // signature unacceptable or expired
      await expect(credentialsUpdater.updateCredential(...invalidParameters)).to.be.revertedWith("CanUpdateCredential");

      // timestamp must be in the past
      invalidParameters = [user, userPolicyId, admissionPolicyId, timestamp + 1000, [signedAttestation.signature]];
      await expect(credentialsUpdater.updateCredential(...invalidParameters)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "updateCredential",
          "timestamp must be in the past"
        )
      );

      // timestamp must be in the past - same in KeyringCredentials
      const credentialsUpdaterRole = await credentials.roleCredentialsUpdater();
      await credentials.grantRole(credentialsUpdaterRole, this.admin);
      await expect(credentials.setCredentialV1(
        user, 
        userPolicyId,
        admissionPolicyId, 
        timestamp + 1000))
      .to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringCredentials",
          "setCredential",
          "timestamp must be in the past"
        )
      );

      await credentials.grantRole(credentialsUpdaterRole, credentialsUpdater.address);

      // verifier addresses from signatures must be sorted in ascending order
      let validParameters: [string, string, string, number, Array<string>];
      const attestation2: Attestation = {
        user: this.alice,
        userPolicyId: userPolicyId,
        admissionPolicyId: admissionPolicyId,
        timestamp: timestamp,
        isRequest: false,
      };
      const signedAttestation2: SignedAttestation = await signAttestation(
        attestation2,
        chainId.toString(),
        verifyingContract,
        verifier1Wallet,
      );
      validParameters = [user, userPolicyId, admissionPolicyId, timestamp, [signedAttestation2.signature, signedAttestation2.signature]];
      await expect(credentialsUpdater.updateCredential(...validParameters)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "updateCredential",
          "verifier addresses from signatures must be sorted in ascending order"
        )
      );

      // credentials are not created when requiredVerifiers is set to 0
      invalidParameters = [user, userPolicyId, admissionPolicyId, timestamp, [signedAttestation.signature]];
      const RULE_ID_GBUS_EXCL_PEP = await ruleRegistry.ruleAtIndex(5);
      await policyManager.updatePolicy(
        admissionPolicyId,
        "Intersection: Union [ GB, US ], Complement [ PEP ], 0 of 2",
        RULE_ID_GBUS_EXCL_PEP,
        0,
        ONE_DAY_IN_SECONDS,
      );
      await expect(credentialsUpdater.updateCredential(...invalidParameters)).to.be.revertedWith(
        unacceptable(
          this.admin,
          "KeyringV1CredentialUpdater",
          "updateCredential",
          "credentials are not created when requiredVerifiers is set to 0",
        ),
      );
    });
  });
});

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

function sortAscendingOrder(ruleIds: string[]) {
  return ruleIds.sort();
}

// function generates custom error message
const unacceptable = (sender: string, module: string, method: string, reason: string) => {
  return `Unacceptable("${sender}", "${module}", "${method}", "${reason}")`;
};
