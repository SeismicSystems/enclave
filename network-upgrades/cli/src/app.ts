import {
    type ShieldedContract,
    type ShieldedWalletClient,
    createShieldedWalletClient,
  } from 'seismic-viem'
  import { Abi, Address, Chain, http } from 'viem'
  import { privateKeyToAccount } from 'viem/accounts'
  
  import { getShieldedContractWithCheck } from '../lib/utils'
  
  /**
   * Configuration for the UpgradeOperator App.
   */
  interface AppConfig {
    privateKey: string
    wallet: {
      chain: Chain
      rpcUrl: string
    }
    contract: {
      abi: Abi
      address: Address
    }
  }
  
  /**
   * A simple application class for interacting with the UpgradeOperator contract.
   */
  export class App {
    private config: AppConfig
    private walletClient!: ShieldedWalletClient
    private contract!: ShieldedContract
  
    constructor(config: AppConfig) {
      this.config = config
    }
  
    /**
     * Initialize the app by creating a shielded wallet client and preparing the contract interface.
     */
    async init() {
      // Create a shielded wallet client using the provided config.
      this.walletClient = await createShieldedWalletClient({
        chain: this.config.wallet.chain,
        transport: http(this.config.wallet.rpcUrl),
        account: privateKeyToAccount(this.config.privateKey as `0x${string}`),
      })
  
      // Grab a shielded contract instance using the provided ABI & address.
      this.contract = await getShieldedContractWithCheck(
        this.walletClient,
        this.config.contract.abi,
        this.config.contract.address
      )
    }
  
    /**
     * Write call to set MRTD data.
     * The rootfsHash is 32 bytes, mrtd/rtmr0/rtmr3 are each 48 bytes, 
     * plus a status boolean to set or unset.
     */
    async setMRTD(
      rootfsHash: `0x${string}`,
      mrtd: `0x${string}`,
      rtmr0: `0x${string}`,
      rtmr3: `0x${string}`,
      status: boolean
    ) {
      console.log(`Calling set_mrtd()...`)
      await this.contract.write.set_mrtd([rootfsHash, mrtd, rtmr0, rtmr3, status])
    }
  
    /**
     * Read call to get the MRTD status for a specific combination of 
     * rootfsHash, mrtd, rtmr0, and rtmr3.
     */
    async getMRTD(
      rootfsHash: `0x${string}`,
      mrtd: `0x${string}`,
      rtmr0: `0x${string}`,
      rtmr3: `0x${string}`
    ): Promise<boolean> {
      console.log(`Calling get_mrtd()...`)
      const result = (await this.contract.read.get_mrtd([rootfsHash, mrtd, rtmr0, rtmr3]) ) as boolean
      console.log(`get_mrtd() returned: ${result}`)
      return result
    }
  }
  