import "@nomiclabs/hardhat-waffle";
import "@nomiclabs/hardhat-etherscan";
import "@typechain/hardhat";
import "@openzeppelin/hardhat-upgrades";
import "hardhat-abi-exporter";
import "hardhat-gas-reporter";
import "hardhat-spdx-license-identifier";
import "solidity-coverage";
import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import "solidity-docgen";

import { HardhatUserConfig } from "hardhat/config";
import { resolve } from "path";
import { config as dotenvConfig } from "dotenv";

import "./tasks/accounts";
import { chainIds, namedAccounts } from "./constants";

import "./tasks/deploy";
import "./tasks/demodata";

dotenvConfig({ path: resolve(__dirname, "./.env") });

const INFURA_API_KEY: string | undefined = process.env.INFURA_API_KEY;
const GOERLI_PRIVATE_KEY: string | undefined = process.env.GOERLI_PRIVATE_KEY;

const config: HardhatUserConfig = {
  abiExporter: {
    path: "./abi",
    clear: false,
    flat: true,
  },
  defaultNetwork: "hardhat",

  networks: {
    hardhat: {
      chainId: chainIds.hardhat,
      allowUnlimitedContractSize: false,
    },
    ...( // only adds if the key is defined
      INFURA_API_KEY && GOERLI_PRIVATE_KEY && {
        goerli: {
          chainId: chainIds.goerli,
          url: "https://goerli.infura.io/v3/" + INFURA_API_KEY,
          accounts: [`${GOERLI_PRIVATE_KEY}`],
        }
      }
    )
  },
  namedAccounts: {
    ...namedAccounts,
  },
  paths: {
    artifacts: "./artifacts",
    cache: "./cache",
    sources: "./contracts",
    tests: "./test",
  },
  solidity: {
    compilers: [
      {
        version: "0.8.14",
        settings: {
          metadata: {
            // Not including the metadata hash
            // https://github.com/paulrberg/solidity-template/issues/31
            bytecodeHash: "none",
          },
          // Disable the optimizer when debugging
          // https://hardhat.org/hardhat-network/#solidity-optimizer-support
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
      {
        version: "0.6.11",
        settings: {
          metadata: {
            bytecodeHash: "none",
          },
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
  },
  typechain: {
    outDir: "src/types",
    target: "ethers-v5",
  },
  spdxLicenseIdentifier: {
    overwrite: false,
    runOnCompile: true,
    except: ["contracts/zkVerifiers", "contracts/interfaces"],
  },
};

export default config;
