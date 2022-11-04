export const chainIds: { [id: string]: number } = {
  goerli: 5,
  hardhat: 1337,
  kovan: 42,
  mainnet: 1,
  rinkeby: 4,
  ropsten: 3,
};

export const namedAccounts: { [name: string]: number } = {
  admin: 0,
  alice: 1,
  bob: 2,
  verifier1: 3,
  verifier2: 4,
  attacker: 5,
};

export const Operator: { [operator: string]: number } = {
  base: 0,
  union: 1,
  intersection: 2,
  complement: 3,
};

export const genesis = {
  universeDescription: "Universe Set (everyone)",
  universeUri: "https://universe.tbd",
  emptyDescription: "Empty Set (no one)",
  emptyUri: "https://empty.tbd"
}

export const testPolicy = {
  description: "Intersection: Union [ GB, US ], Complement [ PEP ] - 1 of 2"
}

export interface Rule {
  // Rule: description, uri, operator, operands
  [ruleName: string]: [string, string, number, string[]];
}

export const baseRules: Rule = {
  PP_GB: ["Passport Issued by: GB", "https://api.keyring.network/gb", Operator.base, []],
  PP_US: ["Passport Issued by: US", "https://api.keyring.network/us", Operator.base, []],
  PEP: ["PEP", "https://api.keyring.network/pep", Operator.base, []],
};
