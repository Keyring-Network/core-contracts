import { parseEther } from "ethers/lib/utils";
import { ContractRoleEvents, RuleCreationProps, TestTokens, Tokens } from "./types";
import { BigNumberish } from "ethers";
import dotenv from "dotenv";
dotenv.config();

export const DEFAULT_FILENAME = "deployment-core.json";

export const MAINNET_ADMIN_ADDRESS = process.env.MAINNET_ADMIN_ADDRESS;
export const MAINNET_AGGREGATOR_ADDRESS = process.env.MAINNET_AGGREGATOR_ADDRESS;
export const MAINNET_WALLET_CHECK = process.env.MAINNET_WALLET_CHECK;

export const GOERLI_ADMIN_ADDRESS = process.env.GOERLI_ADMIN_ADDRESS;
export const GOERLI_AGGREGATOR_ADDRESS = process.env.GOERLI_AGGREGATOR_ADDRESS;
export const GOERLI_WALLET_CHECK = process.env.GOERLI_WALLET_CHECK;

export const WALLETCHECK_URI = "https://roles.keyring.network/walletchecker1";
export const ATTESTOR_URI = "https://roles.keyring.network/attestor1";

export const ONE_DAY_IN_SECONDS = 24 * 60 * 60;
export const MAXIMUM_CONSENT_PERIOD = ONE_DAY_IN_SECONDS * 120; // 120 days;
export const POLICY_DISABLEMENT_PERIOD = ONE_DAY_IN_SECONDS * 60; // 60 days

export const GENESIS_RULE_REGISTRY: Record<string, string> = {
  universeDescription: "Universe Set (everyone)",
  universeUri: "https://rules.keyring.network/0",
  emptyDescription: "Empty Set (no one)",
  emptyUri: "https://rules.keyring.network/1",
};

export const RULE_OPERATORS: { [operator: string]: number } = {
  base: 0,
  union: 1,
  intersection: 2,
  complement: 3,
};

export const BASE_RULES: RuleCreationProps[] = [
  {
    description: `{"version":"1","source":"undefined","process":"complycube","field":"issuer country (alpha-2)","operator":"==","value":"us"}`,
    uri: "https://rules.keyring.network/", // NOTE - get's the current rule count attached e.g. https://rules.keyring.network/2 for the first base rule
    operator: RULE_OPERATORS.base,
    operands: [],
  },
  // NOTE add more base rules if needed...
];

export const ALL_CONTRACT_NAMES = [
  "ExemptionsManager",
  "IdentityTree",
  "KeyringCredentials",
  "PolicyManager",
  "RuleRegistry",
  "WalletCheck",
  "KeyringZkCredentialUpdater",
  // KeyringGuard // NOTE - this is not a standalone contract
];

// NOTE - only used for testing on goerli
// wrapped kyc tokens
export const TEST_TOKENS: TestTokens = {
  USDT: {
    name: "Tether USD",
    symbol: "USDT",
    supply: parseEther("500000000"), // 500M USDT
    kycName: "KYC Tether USD",
    kycSymbol: "kycUSDT",
  },
  WETH: {
    name: "Wrapped Ether",
    symbol: "WETH",
    supply: parseEther("500000000"), // 500M WETH
    kycName: "KYC Wrapped Ether",
    kycSymbol: "kycWETH",
  },
  bIB01: {
    name: "Backed IB01 $ Treasury Bond 0-1yr",
    symbol: "bIB01",
    supply: parseEther("500000"), // 500k bIB01
    kycName: "KYC Backed IB01 $ Treasury Bond 0-1yr",
    kycSymbol: "KYCbIB01",
  },
  USDC: {
    name: "USD Coin",
    symbol: "USDC",
    supply: parseEther("500000000"), // 500M USDC
    kycName: "KYC USD Coin",
    kycSymbol: "kycUSDC",
  },
};

export const WRAPPED_TOKENS: Tokens = {
  USDC: {
    name: "USD Coin",
    symbol: "USDC",
    address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // NOTE - this is the mainnet address
  },
  IB01: {
    name: "Backed IB01 $ Treasury Bond 0-1yr",
    symbol: "bIB01",
    address: "0xca30c93b02514f86d5c86a6e375e3a330b435fb5",
  },
};

// As of Rob 2023-07-07
export const RBD_REGIME_PUBLIC_KEYS: [BigNumberish, BigNumberish][] = [
  [
    "11861472948802330539458928508749370199091896847118098606236732917822682642325",
    "13518738076975985431737840435977119166349170850457317389274941608967928595766",
  ],
];

export const ozNetworkToFilename: Record<string, string> = {
  mainnet: "mainnet",
  goerli: "goerli",
  hardhat: "unknown-1337",
  localhost: "unknown-1337",
};

export const ALL_ROLE_CHANGING_EVENTS: ContractRoleEvents[] = [
  ContractRoleEvents.RoleGranted,
  ContractRoleEvents.RoleRevoked,
];

export const TRANSPARENT_PROXY_ADMIN_ABI = [
  "function getProxyImplementation(address proxy) public view returns (address)",
  "function getProxyAdmin(address proxy) public view returns (address)",
  "function upgrade(address proxy, address implementation) public",
  "function owner() public view returns (address)",
];

// Storage slots for OZ TransparentUpgradeableProxy contract
// Source: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4fb3a89f9d0a39c7ee6f2601d33ffbf30085322/contracts/proxy/transparent/TransparentUpgradeableProxy.sol#L74
export const IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
// Source: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4fb3a89f9d0a39c7ee6f2601d33ffbf30085322/contracts/proxy/transparent/TransparentUpgradeableProxy.sol#L61
export const ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
