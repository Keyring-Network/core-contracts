# runs node in background
npx hardhat compile
npx hardhat node --network hardhat &

# publishing contracts to s3
aws s3 cp --recursive /app/artifacts/contracts/ s3://$CONTRACT_BUCKET/$GIT_SHA

# ensures node is up and then deploys
start=$SECONDS
until npx hardhat deploy --network localhost
do
  echo "Re-attempting deploy in 2s"
  sleep 2
  if (( SECONDS - start > 10 ))
  then
     echo "Giving up..."
     exit 1
  fi
done

# create demodata
npx hardhat demodata --network localhost

# waits until process %1 has finished (i.e. the hardhat node continues)
wait %1