import { MockProvider } from "ethereum-waffle";
import { Wallet } from "ethers";
import path from "path";

export const enum ZK_PROOF_RELEASE {
  "2023-11-30.2" = "2023-11-30.2", // https://github.com/Keyring-Network/keyring-circuits/releases/tag/2023-11-30.2,
  "2023-12-19.1" = "2023-12-19.1", // https://github.com/Keyring-Network/keyring-circuits/releases/tag/2023-12-19.1
}

export const enum ZK_PROOF_TYPE {
  "MERKLE_AUTH" = "MerkleAuth",
}

export const enum ZK_PROOF_NUM {
  zero = 0,
  one = 1,
  two,
  three,
  four,
}

export const getProof = (type: ZK_PROOF_TYPE, position: ZK_PROOF_NUM, release: ZK_PROOF_RELEASE) => {
  try {
    const rootDir = __dirname;
    const filePath = path.join(rootDir, release, `${type}.0${position}.json`);
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const proof = require(filePath);
    return proof;
  } catch (e: any) {
    throw new Error(`Failed to load JSON file: ${e?.message}`);
  }
};

export const getTrader = (position: ZK_PROOF_NUM, release: ZK_PROOF_RELEASE) => {
  try {
    const rootDir = __dirname;
    const filePath = path.join(rootDir, release, `trading_wallet.0${position}.json`);
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const trader = require(filePath);
    return trader;
  } catch (e: any) {
    throw new Error(`Failed to load JSON file: ${e?.message}`);
  }
};

export const getTraderSigner = (provider: MockProvider, position: ZK_PROOF_NUM, release: ZK_PROOF_RELEASE) => {
  try {
    const rootDir = __dirname;
    const filePath = path.join(rootDir, release, `trading_wallet.0${position}.json`);
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const trader = require(filePath);
    return new Wallet(trader.priv, provider);
  } catch (e: any) {
    throw new Error(`Failed to load JSON file: ${e?.message}`);
  }
};
