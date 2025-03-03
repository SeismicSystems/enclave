import dotenv from 'dotenv'
import { join } from 'path'
import { sanvil, seismicDevnet } from 'seismic-viem'

import { CONTRACT_DIR, CONTRACT_NAME } from '../lib/constants'
import { readContractABI, readContractAddress } from '../lib/utils'
import { App } from './app'

dotenv.config()


// Hard-coded data from the Solidity test
const ROOTFS_HASH = '0xb5686a419bbbe59b475ef403083b4cdc22e0d65547aaedf5031c7bc0fd4fac03' as `0x${string}`
const MRTD = '0x7ba9e262ce6979087e34632603f354dd8f8a870f5947d116af8114db6c9d0d74c48bec4280e5b4f4a37025a10905bb29' as `0x${string}`
const RTMR0 = '0x698a1e5764ff07840695fb46c809949cca352e6c9d26fc37dce872402adc071b3b069b0b217c1dcda68cf914253b6842' as `0x${string}`
const RTMR3 = '0x3c30787034cd9aabff0347bc8f08b9f24a0f6ae914bbca0f9aba681e857aa57a7a7cc5b0b67231779cdc345f107707c5' as `0x${string}`


async function main() {
  if (!process.env.CHAIN_ID || !process.env.RPC_URL) {
    console.error('Please set your environment variables.')
    process.exit(1)
  }

  const broadcastFile = join(
    CONTRACT_DIR,
    'broadcast',
    `${CONTRACT_NAME}.s.sol`,
    process.env.CHAIN_ID,
    'run-latest.json'
  )
  const abiFile = join(
    CONTRACT_DIR,
    'out',
    `${CONTRACT_NAME}.sol`,
    `${CONTRACT_NAME}.json`
  )

  const chain =
    process.env.CHAIN_ID === sanvil.id.toString() ? sanvil : seismicDevnet
  console.log("index.ts chain id:", chain.id)


  const app = new App({
    privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    wallet: {
      chain,
      rpcUrl: process.env.RPC_URL!,
    },
    contract: {
      abi: readContractABI(abiFile),
      address: readContractAddress(broadcastFile),
    },
  })

  await app.init()

  // Check that getMRTD() returns false initially
  const initialStatus = await app.getMRTD(ROOTFS_HASH, MRTD, RTMR0, RTMR3)
  console.log('Initial MRTD status:', initialStatus) // Expect false

  // Set MRTD to true
  console.log('Setting MRTD to true...')
  await app.setMRTD(ROOTFS_HASH, MRTD, RTMR0, RTMR3, true)

  // Verify that getMRTD() now returns true
  const updatedStatus = await app.getMRTD(ROOTFS_HASH, MRTD, RTMR0, RTMR3)
  console.log('Updated MRTD status:', updatedStatus) // Expect true



}

main()