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
import { chainIds, namedAccounts } from "./test/constants";

import "./tasks/accounts";
import "./tasks/deploy";
import "./tasks/deploy-tokens";
import "./tasks/owner";
import "./tasks/demodata";
import "./tasks/deploy-demodata-owner";
import "./tasks/gas";
import "./tasks/hasRoles";
import "./tasks/exemptions";
import "./tasks/rolesOwners";
import "./tasks/verify-etherscan";
import "./tasks/upgrade";

dotenvConfig({ path: resolve(__dirname, "./.env") });

const INFURA_API_KEY = process.env.INFURA_API_KEY;
const SEPOLIA_PRIVATE_KEY = process.env.SEPOLIA_DEPLOYER_PRIVATE_KEY || "";
const MAINNET_PRIVATE_KEY = process.env.MAINNET_DEPLOYER_PRIVATE_KEY || "";
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

const config: HardhatUserConfig = {
  etherscan: {
    apiKey: {
      mainnet: ETHERSCAN_API_KEY,
      sepolia: ETHERSCAN_API_KEY,
    },
  },
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
      deploy: ["deploy/index.ts"],
    },
    ...(INFURA_API_KEY &&
      SEPOLIA_PRIVATE_KEY && {
        sepolia: {
          chainId: chainIds.sepolia,
          url: "https://sepolia.infura.io/v3/" + INFURA_API_KEY,
          accounts: [SEPOLIA_PRIVATE_KEY],
          gasMultiplier: 1.5,
        },
      }),
    ...(INFURA_API_KEY &&
      MAINNET_PRIVATE_KEY && {
        mainnet: {
          chainId: chainIds.mainnet,
          url: "https://mainnet.infura.io/v3/" + INFURA_API_KEY,
          accounts: [MAINNET_PRIVATE_KEY],
        },
      }),
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
