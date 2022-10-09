# runs node in background
npx hardhat node --network hardhat &

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