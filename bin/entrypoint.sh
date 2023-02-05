#!/bin/bash

npx hardhat compile

if [[ "$MODULE" != "contract-generation" ]]; then
    # runs hardhat node in foreground
    npx hardhat node --network hardhat
fi