const shell = require("shelljs");

module.exports = {
  istanbulReporter: ["html", "lcov"],
  providerOptions: {
    privateKey: process.env.PRIVATE_KEY,
  },
  skipFiles: [
    "./forwarder/NoImplementation.sol",
    "./mocks/MockERC20.sol"
  ]
};
