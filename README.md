# Keyring Core Smart Contracts

Code for the V1 version

## Install

```
yarn install
```

## Minimal test

```
$ npx hardhat test
```

## Exploring

See `/test/shared/fixtures.ts` for a deployment sequence.

- the first account is the deployer and gets the DEFAULT_ADMIN_ROLE for all contracts (super-user)
- Internal trusts are established
  - cache trusts cacheUpdater for cache updates
  - groupRegistry trusts policyManager for dependencyUpdates
- Operational trusts are granted to the deployer
  - kycAdmin can admit a kyc signer into the list of acceptable kycsigners to use in admissionPolicies
  - groupMaster can establish and remove groups to use in inclusion/exclusion lists
