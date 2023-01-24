import { ethers } from "ethers";
import { IKeyringZkVerifier } from "./src/types";

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
  attestor1: 3,
  attestor2: 4,
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
  emptyUri: "https://empty.tbd",
};

export interface Rule {
  // Rule: description, uri, operator, operands
  [ruleName: string]: [string, string, number, string[]];
}

export const baseRules: Rule = {
  PP_GB: ["Passport Issued by: GB", "https://api.keyring.network/gb", Operator.base, []],
  PP_US: ["Passport Issued by: US", "https://api.keyring.network/us", Operator.base, []],
  PEP: ["PEP", "https://api.keyring.network/pep", Operator.base, []],
};

export const ROLE_GLOBAL_ATTESTOR_ADMIN = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("rgaa"));
export const ROLE_RULE_ADMIN = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("role rule admin"));
export const ROLE_WALLET_CHECK_ADMIN = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("wallet check admin role"));
export const ROLE_AGGREGATOR = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("aggregator role"));

export const THIRTY_DAYS_IN_SECONDS = 24 * 60 * 60 * 30;
export const ONE_DAY_IN_SECONDS = 24 * 60 * 60;
export const NULL_ADDRESS = ethers.constants.AddressZero;
export const NULL_BYTES32 = ethers.constants.HashZero;

/* -------------------------------------------------------------------------- */
/*                                  PROOF #1                                  */
/* -------------------------------------------------------------------------- */
/* ------------------------------- Merkle Root ------------------------------ */
// hardocded merkle root (first signal in the calldata) from:
// https://github.com/Keyring-Network/keyring-circuits/blob/cleanup/audit/dist/circuits/semaphore.calldata
export const proofMerkleRoot = "0x1fad8de558447cd0fce868283cee58c9cba2d2a2bb2d210100c29eb5e20b9686";
export const trader = "0x44017a895f26275166b1d449BCb1573fD324b456";
/* --------------------------- Authorisation Proof -------------------------- */
// hardcoded proof from:
// https://github.com/Keyring-Network/keyring-circuits/blob/cleanup/audit/dist/circuits/authorisation.calldata
export const authorisationProof: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
  proof: {
    a: [
      "0x2459cbdaf5fc80ab9153c833dd0892c8daecfbb6117e6cd03f5bfd1321933f56",
      "0x2f2b815c230ee82c112c6405fde1b0b1589ae2cdf3eecd043981257baa2d5557",
    ],
    b: [
      [
        "0x2f1fba495b1e92a0c32babb56dcac78606a4870c255330640837af0c7d223e20",
        "0x21a016912238977261ea3c7d0a27f8357fc5548877dea6e8a17de9c46d108115",
      ],
      [
        "0x28cd2700f914c938d17e02078cc2ea7995f37a1d2fd6095764e795db5954dca3",
        "0x1d39cc9cedc2d4766048affbaa6bcc9a39a936f532bfe4e586bdd574d4b145b1",
      ],
    ],
    c: [
      "0x28d40e9edb78577d464b8f31b2e8fc5405ee0f8c01597117256bcf4067364366",
      "0x1a3654b9b95a967180b3c1516b1cb74583173b044cd394393856fb8b8415aba6",
    ],
  },
  externalNullifier: "0x0000000000000000000000000000000000000000000000000000000000000001",
  nullifierHash: "0x157f1066190cb6fcf0d89ef6ef75c015121ad90ec1a9ceffcbab088d7ec743a0",
  policyDisclosures: [
    "0x00000000100002000030000400005000060000700008000090000a0000b0000c",
    "0x000001000fffff00000000000000000000000000000000000000000000000000",
  ],
  tradingAddress: "0x00000000000000000000000044017a895f26275166b1d449bcb1573fd324b456",
};

/* ---------------------------- Membership Proof ---------------------------- */
// hardcoded proof from:
// https://github.com/Keyring-Network/keyring-circuits/blob/cleanup/audit/dist/circuits/semaphore.calldata
export const membershipProof: IKeyringZkVerifier.IdentityMembershipProofStruct = {
  proof: {
    a: [
      "0x29fc1f44076c58ee890c7d798f1d75a8b002a0f1474cd8c66de4ab1b0a1e193c",
      "0x211312ea0d9ac5c9a933f9793e8de5d96514526bc0ee62f6ea8bc0edc81c3e23",
    ],
    b: [
      [
        "0x237efa2e1bbbda718527078db701997dd5d64a0ef7cc3c761f1359ff45ffdf60",
        "0x22f23b059c08ac4e35f7801c051c963083d5e0174f21ffb8d182189473c8bda3",
      ],
      [
        "0x1122f41777094aacadc3d6bb623733a3a10ddfd3cf2e6122813d2c2f874b9cf9",
        "0x023b5e0b18cf359843132a17b4614f0f57d489a6302192da23b9a5b67b8da5b5",
      ],
    ],
    c: [
      "0x106be252ddd79aeca0663af67fd58a8a07298125c79cafc937709cfadb04be70",
      "0x1f60b14013582ef607db1989e1f29b6554dc6d1f827bd8571df848a473974bbf",
    ],
  },
  root: "0x1fad8de558447cd0fce868283cee58c9cba2d2a2bb2d210100c29eb5e20b9686",
  nullifierHash: "0x157f1066190cb6fcf0d89ef6ef75c015121ad90ec1a9ceffcbab088d7ec743a0",
  signalHash: "0x0020463d390a03b6e100c5b7cef5a5ac0808b8afc4643ddbdaf1057c610f2ea1",
  externalNullifier: "0x0000000000000000000000000000000000000000000000000000000000000001",
};

/* --------------------------- Construction Proof --------------------------- */
// hardcoded proof from:
// https://github.com/Keyring-Network/keyring-circuits/blob/cleanup/audit/dist/circuits/construction.calldata
export const constructionProof: IKeyringZkVerifier.IdentityConstructionProofStruct = {
  proof: {
    a: [
      "0x00b19e4dcf9a7192f02e95b160ff3cd2101c240b3263955ec648598a79f1325c",
      "0x2509d4c1753cdfb2bad2888291a50b324840e617183e7b919214300345328aae",
    ],
    b: [
      [
        "0x0d05fb10e00823dc902e734665f1546e53c0545bcd5f61caa074115c54699d54",
        "0x0469e3c1a1ad18e64718d2ee33aef6d2daec9fccee69460fc74ed845a02db5bf",
      ],
      [
        "0x07263e7f42ec783277bc6d12f67e027596ddbaeb3c52328b324852c0c0b5aedc",
        "0x29f8da94180deed2027ed39c512d5b5d06a854adcbbd239fbc525b656b7a5896",
      ],
    ],
    c: [
      "0x18388026af7097532adac86a9d347fcd92dfec4e8b621f3c538fd28ec81007b2",
      "0x02c539be4715b45f86c61bb850c086969d65256bf5c1f84af879e52ee2d0c67d",
    ],
  },
  identity: "0x1d6487472dfb4527dc5127afd1f7372295c56301fd3d2dd93e57e3d55282431f",
  policyCommitment: "0x28a907f8ab71f2626449579031ed7d886cd6a9f64d3472832c9faba87eb1a06b",
  maxAddresses: "0x0000000000000000000000000000000000000000000000000000000000000003",
};

/* -------------------------------------------------------------------------- */
/*                                 PROOF #2.1                                 */
/* -------------------------------------------------------------------------- */
// from: https://github.com/Keyring-Network/keyring-circuits/pull/4/commits/9b10de222465e77cdbcce57b9e36d1211694edcf
/* ------------------------------- Merkle Root ------------------------------ */
export const proofMerkleRoot2 = "0x11cb366a5c27b20da04d7b7b1d6d64543ebf17172822986fcdd0acb38f468c93";
export const trader2 = {
  priv: "0xf3781d0ccc3d1c5ba9e000a5f03353b83d443cd587cc0c11a844d65c9b4b8d68",
  address: "0x00D6EB84Ce9A1BeC26B9675346e168D20636DbeC",
};
/* --------------------------- Authorisation Proof -------------------------- */
export const authorisationProof2: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
  proof: {
    a: [
      "0x1204da9e8b3031744170ec232581600f9bb083b501314236b9326a883522eb2e",
      "0x11bb48d0866bba90a8211f1aca34fda63acc192efda280e1a68b7ec12904aa07",
    ],
    b: [
      [
        "0x10749fb7ecf3a999cc21c03a856fabf3bbf1ab58388c5671400eb72894d1a06a",
        "0x19032ce0bc9b7413b778545750783ffe2432229d789b8a824004003717e70113",
      ],
      [
        "0x0ed875b12690bb4a5ffe07fe222153f4e74a7f2ecc236a9a73a13286eda1767c",
        "0x1c638ed776f2b3e03a1eb658da918c97ebf0cbc65926409249e0072aed28cdf0",
      ],
    ],
    c: [
      "0x0d428a01415a84c5a0bfe46a923ac3ae5c4a7ab6becc4ef78cddb796758de015",
      "0x03b94b6e165b502415f3eee44f438490de679487a9c42db8b05641847df46c8f",
    ],
  },
  externalNullifier: "0x0000000000000000000000000000000000000000000000000000000000000001",
  nullifierHash: "0x00e9dfba4a6727286830d3e704b62fd7d55419c25c48534521b7e6475925be62",
  policyDisclosures: [
    "0x00000000100002000030000400005000060000700008000090000a0000b0000c",
    "0x00000000d0000e0000f000100000000000000000000000000000000000000000",
  ],
  tradingAddress: "0x00000000000000000000000000d6eb84ce9a1bec26b9675346e168d20636dbec",
};

/* ---------------------------- Membership Proof ---------------------------- */
export const membershipProof2: IKeyringZkVerifier.IdentityMembershipProofStruct = {
  proof: {
    a: [
      "0x012f307ea1e9fdd8af268e3fa0465c201a98fa843bb7b0b2fea16d80cb4df80e",
      "0x19cdf0ac6dc21099090fc1a68b1315ec130fc212c577a680c96a2f2e14dc320c",
    ],
    b: [
      [
        "0x25e059ec31b7bffc10159e2dca3bfc8e5d61a72c202f79a1a84f000bcd6b3a06",
        "0x0e967791da58d4c87bd8a2840714fa00a6a12bde0981c9fb3fb867497720311d",
      ],
      [
        "0x0aae6f1b2629312acf51799387e395b5dfd6fee7781e306b391519ed4c7dad93",
        "0x1a76e50dfdabb3176d89053c4a0b691d55a9c1e54f97ff125f066e80bbf82e78",
      ],
    ],
    c: [
      "0x0ed55d967a218dc8dec1346c03d98ae719bcb5b0902dc895325aaee1283c6807",
      "0x1b432bb0a042c3a6c2836f634b0e0e0813e2e14b842b98156e286e7e7262b5ab",
    ],
  },
  root: "0x11cb366a5c27b20da04d7b7b1d6d64543ebf17172822986fcdd0acb38f468c93",
  nullifierHash: "0x00e9dfba4a6727286830d3e704b62fd7d55419c25c48534521b7e6475925be62",
  signalHash: "0x0020463d390a03b6e100c5b7cef5a5ac0808b8afc4643ddbdaf1057c610f2ea1",
  externalNullifier: "0x0000000000000000000000000000000000000000000000000000000000000001",
};

/* --------------------------- Construction Proof --------------------------- */
export const constructionProof2: IKeyringZkVerifier.IdentityConstructionProofStruct = {
  proof: {
    a: [
      "0x241724adeeb9f96193fb8f636f10a51400cd57dab7d713ba2f2fe0c6e5b7db9b",
      "0x16d32638d49e841d2d7edde3701a0ad8e57e589c1f8a768f2b830386447b35a5",
    ],
    b: [
      [
        "0x19e959e7c9d4dd403215885dda6f49542c3343ef1cd2a3805395fd5c1d5e3094",
        "0x10e688bc12793d8f96e0aa3c37694a6edc88cd776ae2c0b16270da377fc9fa72",
      ],
      [
        "0x11de7392378e8644c77701d2e9de9d7f7a5523c145025e2c8e8b0bf7b704a244",
        "0x03a361f1e58d620bb210c78bbdd8858821e38c60af6cf4ad73569b28ab0a58ea",
      ],
    ],
    c: [
      "0x028050bb7c8e8aed6a4e6ac1bb051da04de597c3998ca3738a1146126b17d95a",
      "0x2413901b4f76aa92abc5b1226b51f10355171e8329033f167b23772f14d0f4ff",
    ],
  },
  identity: "0x2fa686cac6c068d4f89f58f4f24d7093115b52bd699e1bf275740c56f473c807",
  policyCommitment: "0x0770aeb0bee89d68959da0f89007d9e01b82696b90c06bb68da26a05ba58041d",
  maxAddresses: "0x0000000000000000000000000000000000000000000000000000000000000003",
};

/* -------------------------------------------------------------------------- */
/*                                  PROOF #3                                  */
/* -------------------------------------------------------------------------- */
// from: https://github.com/Keyring-Network/keyring-circuits/pull/4/commits/c494455d803b53fb11beb60fef2fe761bd37af3e#diff-bc881aa78e75f1a4d0e12516199d8e7f09bde6b1d13b748fd826352066026988
/* ------------------------------- Merkle Root ------------------------------ */
export const proofMerkleRoot3 = "0x24fe730bc6daa8dc772a0e3613577e04e6ff079bcf04e198b3aa9b814017e2a1";
export const trader3 = {
  priv: "4ed31a67a7744b29723faa4b66b6b10fc602b34db1c8948b9a429ee22e169ee7",
  address: "0x07CD88124041B57b93cE49189D24861952A16443",
};
/* --------------------------- Authorisation Proof -------------------------- */
export const authorisationProof3: IKeyringZkVerifier.IdentityAuthorisationProofStruct = {
  proof: {
    a: [
      "0x00b6a0d4077c09e10e50ed61b5ef7ecf4aee9087635e82949967c3a8d4432bab",
      "0x0828e1761ad5edcef8253c2c059f1773b031e044012ada6b0aabe590e1121de8",
    ],
    b: [
      [
        "0x2cad8186b5a16a0d721a1f6c65f2a232fc48c250d8b2396218a56e080719cc5c",
        "0x268d13e87d5bf4ed28968ba07843079c9940fe6913d7d85837091467b443794d",
      ],
      [
        "0x113121fcead3b7fe185cebbca4cc9618015860a32f61c6a0504d5f3c9769e091",
        "0x117d8fc60cddf32dd666e88f7e38dfae6b9c51154160886091f75aecf4409755",
      ],
    ],
    c: [
      "0x27810079f969925853483838cac0803a0f48d6528457e2699b393667ce3ee02a",
      "0x2c44bdf790ddb63e267a28d54eb7a663625a97bf39b8efbeeb2cb0b5a5d6b18e",
    ],
  },
  externalNullifier: "0x0000000000000000000000000000000000000000000000000000000000000001",
  nullifierHash: "0x0add631edcfe8a26657a2cec7282499ed6e50b825fd1edc32804246a0f7adb5a",
  policyDisclosures: [
    "0x00000000100002000030000400005000060000700008000090000a0000b0000c",
    "0x00000000d0000e0000f000100000000000000000000000000000000000000000",
  ],
  tradingAddress: "0x00000000000000000000000007cd88124041b57b93ce49189d24861952a16443",
};

/* ---------------------------- Membership Proof ---------------------------- */
export const membershipProof3: IKeyringZkVerifier.IdentityMembershipProofStruct = {
  proof: {
    a: [
      "0x1cf5980df6d448ad83a315208c34bedfbca0fec0e026754f52651190f482ccd3",
      "0x27075b132b6a9a9ad9e4b440ad2965ddec38c9831368ef0b94297a9c6767288c",
    ],
    b: [
      [
        "0x14b21847b724e888fc3d1e799c0056f16cb950b9a856dd805d93f1263570ba1d",
        "0x22c8012ac0269164c3d512e93ced6cd40b6ed6e151816b3d51bfebffd8de4d6e",
      ],
      [
        "0x0192569405ecc1efa1a249e9c925b93eb3c5972e692910c71fc2e475204f2d1d",
        "0x0ca0c1a629a174ca53dbbbd2a9bd5ebbfe57b3bec24a5e0e197d32705ed399bf",
      ],
    ],
    c: [
      "0x161a3da7f0301461c32667c8896d0b4119ee816996949bd8d13747fcb72f10bb",
      "0x1fede9bcb13de90ad694f98929a09b050339a898c943c00d21e57a14112fcfa3",
    ],
  },
  root: "0x24fe730bc6daa8dc772a0e3613577e04e6ff079bcf04e198b3aa9b814017e2a1",
  nullifierHash: "0x0add631edcfe8a26657a2cec7282499ed6e50b825fd1edc32804246a0f7adb5a",
  signalHash: "0x0020463d390a03b6e100c5b7cef5a5ac0808b8afc4643ddbdaf1057c610f2ea1",
  externalNullifier: "0x0000000000000000000000000000000000000000000000000000000000000001",
};

/* --------------------------- Construction Proof --------------------------- */
export const constructionProof3: IKeyringZkVerifier.IdentityConstructionProofStruct = {
  proof: {
    a: [
      "0x20abf018087f38892fca3e7500b605fe15399bf2616204b0b6a8f87dbde4c43a",
      "0x24f64ca4ec140e62ba03fe4cf6fec0d5507e90a11d5d9b2d8c586c448ec58261",
    ],
    b: [
      [
        "0x1590f058a21970026f3c480e85dc40939128a935b0ed67586caf9d83feb7e83f",
        "0x109f5f128b3a40c5a399508a0c3b41924eb5251350ba8460198746af204ba87c",
      ],
      [
        "0x0271d7810bcbaae25dfe8c1cc4cc27913575370751c11d873ed9fb9ab7486127",
        "0x217a3cfcefb49b2af35388782e824f354d563111ed74c6aaac7673e55fc111a1",
      ],
    ],
    c: [
      "0x15c55e788c3e7fcf3d35390697d77b1d28ed7876b81e6260d671ffa5f5cc766a",
      "0x041f2516a218b92cb7627f9a6f0fe0d8aff98e3aaf8fe9b6b2fb786b8e0140a9",
    ],
  },
  identity: "0x1d2bea604b3896c21cb406eb7569fa157b45bb0aeb7c34f0ca08fd512a783f96",
  policyCommitment: "0x0770aeb0bee89d68959da0f89007d9e01b82696b90c06bb68da26a05ba58041d",
  maxAddresses: "0x0000000000000000000000000000000000000000000000000000000000000003",
};
