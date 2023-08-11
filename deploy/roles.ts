import { keccak256, toUtf8Bytes } from "ethers/lib/utils";
import { ContractRoles } from "./types";

export const ALL_CONTRACT_ROLES: ContractRoles = {
  ExemptionsManager: ["DEFAULT_ADMIN_ROLE", "ROLE_GLOBAL_EXEMPTIONS_ADMIN"],
  IdentityTree: ["DEFAULT_ADMIN_ROLE", "ROLE_SERVICE_SUPERVISOR", "ROLE_AGGREGATOR"],
  KeyringCredentials: ["DEFAULT_ADMIN_ROLE", "ROLE_CREDENTIAL_UPDATER", "ROLE_SERVICE_SUPERVISOR"],
  PolicyManager: [
    "DEFAULT_ADMIN_ROLE",
    "ROLE_POLICY_CREATOR",
    "ROLE_GLOBAL_ATTESTOR_ADMIN",
    "ROLE_GLOBAL_WALLETCHECK_ADMIN",
    "ROLE_GLOBAL_BACKDOOR_ADMIN",
    "ROLE_GLOBAL_VALIDATION_ADMIN",
    "POLICY_OWNER_ROLE_1",
    "POLICY_OWNER_ROLE_2",
    "POLICY_OWNER_ROLE_3",
    "POLICY_OWNER_ROLE_4",
    "POLICY_OWNER_ROLE_5",
    "POLICY_USER_ADMIN_ROLE_1",
    "POLICY_USER_ADMIN_ROLE_2",
    "POLICY_USER_ADMIN_ROLE_3",
    "POLICY_USER_ADMIN_ROLE_4",
    "POLICY_USER_ADMIN_ROLE_5",
    // NOTE - add more `POLICY_OWNER_ROLE` and `POLICY_USER_ADMIN_ROLE` roles if needed
  ],
  RuleRegistry: ["DEFAULT_ADMIN_ROLE", "ROLE_RULE_ADMIN"],
  WalletCheck: [
    "DEFAULT_ADMIN_ROLE",
    "ROLE_SERVICE_SUPERVISOR",
    "ROLE_WALLETCHECK_META_ADMIN",
    "ROLE_WALLETCHECK_LIST_ADMIN",
  ],
  KeyringZkCredentialUpdater: ["DEFAULT_ADMIN_ROLE"],
};

export const ADMIN_CONTRACT_ROLES: ContractRoles = {
  ExemptionsManager: ["DEFAULT_ADMIN_ROLE", "ROLE_GLOBAL_EXEMPTIONS_ADMIN"],
  IdentityTree: ["DEFAULT_ADMIN_ROLE", "ROLE_SERVICE_SUPERVISOR"],
  KeyringCredentials: ["DEFAULT_ADMIN_ROLE", "ROLE_SERVICE_SUPERVISOR"],
  PolicyManager: [
    "DEFAULT_ADMIN_ROLE",
    "ROLE_POLICY_CREATOR",
    "ROLE_GLOBAL_ATTESTOR_ADMIN",
    "ROLE_GLOBAL_WALLETCHECK_ADMIN",
    "ROLE_GLOBAL_BACKDOOR_ADMIN",
    "ROLE_GLOBAL_VALIDATION_ADMIN",
    "POLICY_OWNER_ROLE_1",
    "POLICY_USER_ADMIN_ROLE_1",
    // TODO - adjust roles based on the number of deployed policies
  ],
  RuleRegistry: ["DEFAULT_ADMIN_ROLE", "ROLE_RULE_ADMIN"],
  WalletCheck: ["DEFAULT_ADMIN_ROLE", "ROLE_SERVICE_SUPERVISOR", "ROLE_WALLETCHECK_META_ADMIN"],
  KeyringZkCredentialUpdater: ["DEFAULT_ADMIN_ROLE"],
};

// NOTE - The deployer receives these roles automatically during deploy and init of the contracts
export const DEPLOYER_CONTRACT_ROLES: ContractRoles = {
  ExemptionsManager: ["DEFAULT_ADMIN_ROLE"],
  IdentityTree: ["DEFAULT_ADMIN_ROLE"],
  KeyringCredentials: ["DEFAULT_ADMIN_ROLE"],
  PolicyManager: [
    "DEFAULT_ADMIN_ROLE",
    "POLICY_OWNER_ROLE_1",
    "POLICY_USER_ADMIN_ROLE_1",
    // TODO - adjust roles based on the number of deployed policies
  ],
  RuleRegistry: ["ROLE_RULE_ADMIN", "DEFAULT_ADMIN_ROLE"],
  WalletCheck: ["ROLE_WALLETCHECK_META_ADMIN", "DEFAULT_ADMIN_ROLE"],
  KeyringZkCredentialUpdater: ["DEFAULT_ADMIN_ROLE"],
};

export const AGGREGATOR_CONTRACT_ROLES: ContractRoles = {
  IdentityTree: ["ROLE_AGGREGATOR"],
};
export const WALLET_CHECK_CONTRACT_ROLES: ContractRoles = {
  WalletCheck: ["ROLE_WALLETCHECK_LIST_ADMIN"],
};

export const CREDENTIAL_UPDATER_1_CONTRACT_ROLES: ContractRoles = {
  KeyringCredentials: ["ROLE_CREDENTIAL_UPDATER"],
};

export const ROLE_TO_ID: Record<string, string> = {
  DEFAULT_ADMIN_ROLE: "0x0000000000000000000000000000000000000000000000000000000000000000",
  ROLE_GLOBAL_EXEMPTIONS_ADMIN: keccak256(toUtf8Bytes("x")),
  ROLE_SERVICE_SUPERVISOR: keccak256(toUtf8Bytes("supervisor")),
  ROLE_AGGREGATOR: keccak256(toUtf8Bytes("aggregator role")),
  ROLE_CREDENTIAL_UPDATER: keccak256(toUtf8Bytes("Credentials updater")),
  SEED_POLICY_OWNER: keccak256(toUtf8Bytes("spo")), // not used on its own
  ROLE_POLICY_CREATOR: keccak256(toUtf8Bytes("c")),
  ROLE_GLOBAL_ATTESTOR_ADMIN: keccak256(toUtf8Bytes("a")),
  ROLE_GLOBAL_WALLETCHECK_ADMIN: keccak256(toUtf8Bytes("w")),
  ROLE_GLOBAL_BACKDOOR_ADMIN: keccak256(toUtf8Bytes("b")),
  ROLE_GLOBAL_VALIDATION_ADMIN: keccak256(toUtf8Bytes("v")),
  ROLE_RULE_ADMIN: keccak256(toUtf8Bytes("role rule admin")),
  ROLE_WALLETCHECK_META_ADMIN: keccak256(toUtf8Bytes("wallet check meta admin")),
  ROLE_WALLETCHECK_LIST_ADMIN: keccak256(toUtf8Bytes("wallet check list admin role")),
  POLICY_OWNER_ROLE_1: "0x0000000000000000000000000000000000000000000000000000000000000001",
  POLICY_OWNER_ROLE_2: "0x0000000000000000000000000000000000000000000000000000000000000002",
  POLICY_OWNER_ROLE_3: "0x0000000000000000000000000000000000000000000000000000000000000003",
  POLICY_OWNER_ROLE_4: "0x0000000000000000000000000000000000000000000000000000000000000004",
  POLICY_OWNER_ROLE_5: "0x0000000000000000000000000000000000000000000000000000000000000005",
  POLICY_USER_ADMIN_ROLE_1: "0x1a768be622be34e6bcfd3ddab6d124ad51b7ab6380747cde01fbeb67da89afcc", // can only be assigned by keyring, this role can assign/rewoke POLICY_OWNER_ROLE roles
  POLICY_USER_ADMIN_ROLE_2: "0x654981be9c23e7fd8b7d79f6215505161689676bd3aeefbfa31559d29ce14425",
  POLICY_USER_ADMIN_ROLE_3: "0x804fc66111783cbabf47571d4948902a48571dfced66834770eed25147775a4c",
  POLICY_USER_ADMIN_ROLE_4: "0x31531dbd5cefe3da57c66bbae5481ff813bd883a67ac7b1a627ae43c2215627a",
  POLICY_USER_ADMIN_ROLE_5: "0x9852f275dfa9c87346da3cacc0b2aa377eb174e7a49aa5af4411d98792422075",
  // NOTE - add more `POLICY_OWNER_ROLE` and `POLICY_USER_ADMIN_ROLE` roles if needed
};