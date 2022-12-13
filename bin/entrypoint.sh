#!/bin/bash

npx hardhat compile

if [[ "$MODULE" == "hardhat-node" ]]; then
    # runs hardhat node in foreground
    npx hardhat node --network hardhat
fi