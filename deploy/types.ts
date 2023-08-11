import { BigNumber, Contract, ContractFactory, BytesLike, BigNumberish, ethers } from "ethers";

export interface ContractRoles {
  [contractName: string]: string[];
}

interface RoleDetails {
  name: string;
  id: string;
}

export interface ContractRolesWithDetails {
  [contract: string]: RoleDetails[];
}

export interface ContractInfo {
  name: string;
  address: string;
  abi: string;
  constructorArgs?: unknown[];
  isProxy?: boolean;
  implementationAddress?: string;
  libraries?: Record<string, string>;
}

interface ContractInfos {
  [key: string]: {
    address: string;
    abi: string;
    constructorArgs: unknown[];
    isProxy: boolean;
    implementationAddress?: string;
    libraries?: Record<string, string>;
  };
}

interface UserWithRoles {
  name: string;
  address: string;
  granted: ContractRolesWithDetails | [];
}

export interface DeploymentInfo {
  roles: UserWithRoles[];
  contracts: ContractInfos;
  upgradable?: Record<string, unknown>; // openzeppelin/upgrades
  tokenInfo?: any;
  blockNumber?: number; // block number when the deployment script was run
  commitHash?: string; // commit hash when the deployment script was run
}

export interface ContractInit {
  contract: Contract;
  args?: unknown[];
}

export enum RoleOperation {
  Grant = "grantRole",
  Renounce = "renounceRole",
}

export interface Tokens {
  [key: string]: Token;
}

type Token = {
  name: string;
  symbol: string;
  address: string;
};

export interface TestTokens {
  [key: string]: TestToken;
}

type TestToken = {
  name: string;
  symbol: string;
  supply: BigNumber;
  kycName: string;
  kycSymbol: string;
};

type UnsafeAllowType =
  | "constructor"
  | "delegatecall"
  | "state-variable-immutable"
  | "selfdestruct"
  | "state-variable-assignment"
  | "external-library-linking"
  | "struct-definition"
  | "enum-definition"
  | "missing-public-upgradeto";
type proxyKind = "uups" | "transparent" | undefined;

export interface ProxyOptions {
  unsafeAllow: UnsafeAllowType[];
  kind?: proxyKind;
}

export interface ContractList {
  name: string;
  contract: Contract;
  factory: ContractFactory;
  isProxy?: boolean;
  implementationAddress?: string;
  constructorArgs?: unknown[];
  libraries?: Record<string, string>;
}

/**
 * @notice ordner: description, uri, operator, operands
 */
export type RuleCreationProps = {
  description: string;
  uri: string;
  operator: BigNumberish;
  operands: BytesLike[];
};

export type ContractEvent = {
  blockNumber: number;
  eventFragment: ethers.utils.EventFragment;
  name: string;
  signature: string;
  topic: string;
  args: ethers.utils.Result;
  contract: string;
  type: string;
};

export type EventTopic = {
  name: string;
  topic: string;
};

export enum ContractRoleEvents {
  RoleGranted = "RoleGranted",
  RoleRevoked = "RoleRevoked",
}

export type RoleOwners = {
  contract: string;
  roles: Set<string>;
};

export type Snapshot = {
  timestamp: Date | number;
  startBlock: number;
  endBlock: number;
};
