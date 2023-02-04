#!/bin/bash

if [[ "$MODULE" == "hardhat-node" ]]; then
    # runs hardhat node in foreground
    npx hardhat node --network hardhat
else
    # complies contracts
    npx hardhat compile
fi