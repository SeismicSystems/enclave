cd ~/enclave/network-upgrades/contracts/
sforge test
cp .env.example .env
source .env
sforge script script/UpgradeOperator.s.sol:UpgradeOperatorScript \
      --rpc-url $RPC_URL \
      --broadcast

cd ~/enclave/network-upgrades/cli
cp .env.example .env
source .env
bun dev
