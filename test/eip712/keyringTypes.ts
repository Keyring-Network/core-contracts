export const typedMessage = {
  primaryType: "Attestation",
  domain: {
    name: "Keyring",
    version: "1",
    chainId: "",
    verifyingContract: "",
  },

  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
    Attestation: [
      { name: "user", type: "address" },
      { name: "userPolicyId", type: "bytes32"},
      { name: "admissionPolicyId", type: "bytes32" },
      { name: "timestamp", type: "uint256" },
      { name: "isRequest", type: "bool" },
    ],
  },
};
