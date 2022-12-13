#!/bin/bash

npx hardhat compile

# publishing contracts to s3

if [[ "$MODULE" == "hardhat-node" ]]; then
    # runs hardhat node in foreground
    npx hardhat node --network hardhat
fi