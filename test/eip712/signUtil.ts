import { Wallet } from "ethers";

import { typedMessage as KeyringTypes } from "./keyringTypes";

export interface Attestation {
  user: string;
  userPolicyId: string;
  admissionPolicyId: string;
  timestamp: number;
  isRequest: boolean;
}

export interface SignedAttestation {
  domain: object;
  types: any;
  primaryType: string;
  message: Attestation;
  signature: string;
}

interface EIP712TypedAttestation {
  domain: object;
  types: any;
  primaryType: string;
  message: Attestation;
}

/**
 * @notice returns a complete typed attestion
 * @param attestation type attestion struct
 * @param chainId issuer's chain id
 * @param verifyingContract verifying contract
 * @returns EIP612 typed attestation
 */

async function EIP712TypedAttestation(
  attestation: Attestation,
  chainId: string,
  verifyingContract: string,
): Promise<EIP712TypedAttestation> {
  const domain = KeyringTypes.domain;
  domain.verifyingContract = verifyingContract;
  domain.chainId = chainId;
  const attestationTypes = KeyringTypes.types.Attestation;

  const typedData: EIP712TypedAttestation = {
    domain: domain,
    types: { Attestation: attestationTypes },
    primaryType: "Attestation",
    message: {
      user: attestation.user,
      userPolicyId: attestation.userPolicyId,
      admissionPolicyId: attestation.admissionPolicyId,
      timestamp: attestation.timestamp,
      isRequest: attestation.isRequest,
    },
  };
  return typedData;
}

/**
 * @notice sign an attestation for a specific receiving contract using the signer wallet
 * @param attestation attestation struct
 * @param chainId issuer chain id
 * @param verifyingContract verifying contract address
 * @param wallet Signer with address to sign the attestation
 * @returns
 */

async function _signAttestation(
  attestation: Attestation,
  chainId: string,
  verifyingContract: string,
  wallet: Wallet,
): Promise<SignedAttestation> {
  const typedAttestation = await EIP712TypedAttestation(attestation, chainId, verifyingContract);

  const signature = await wallet._signTypedData(
    typedAttestation.domain,
    typedAttestation.types,
    typedAttestation.message,
  );

  const signedAttestation: SignedAttestation = {
    domain: typedAttestation.domain,
    types: typedAttestation.types,
    primaryType: "Attestation",
    message: typedAttestation.message,
    signature: signature,
  };

  return signedAttestation;
}

/**
 * @param attestation the message to sign contains userId (subject), procedureId, timestamp (now), and isRequest (purpose)
 * @param chainId chainId of contract to verify the signature (ultimate recipient)
 * @param verifyingContract  address of contract to verify the signature (ultimate recipient)
 * @param wallet SignerWithAddress object will sign with the wallet._signTypedData() method.
 * @returns SignedAttestation contains the message contents, destination, EIP712 field types and domain and the signature.
 */

export const signAttestation = async function (
  attestation: Attestation,
  chainId: string,
  verifyingContract: string,
  wallet: Wallet,
): Promise<SignedAttestation> {
  return _signAttestation(attestation, chainId, verifyingContract, wallet);
};
