#!/bin/bash

npx hardhat compile

# publishing contracts to s3
aws s3 cp --recursive /app/artifacts/contracts/ s3://$CONTRACT_BUCKET/$GIT_SHA

if [[ "$MODULE" == "hardhat-node" ]]; then
    # runs hardhat node in foreground
    npx hardhat node --network hardhat
fi