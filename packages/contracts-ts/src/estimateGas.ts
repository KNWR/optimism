import { gasPriceOracleABI, gasPriceOracleAddress } from "./constants"
import { getContract, createPublicClient, http, BlockTag } from 'viem'
import * as chains from 'viem/chains'
import { PublicClient } from "wagmi"

/**
 * Bytes type representing a hex string with a 0x prefix
 * @typedef {`0x${string}`} Bytes
 */
export type Bytes = `0x${string}`

/**
 * BlockOptions type
 * @typedef {Object} BlockOptions
 * @property {bigint} [blockNumber] - Block number
 * @property {BlockTag} [blockTag] - Block tag
 */
type BlockOptions = {
  blockNumber?: bigint | undefined
  blockTag?: BlockTag | undefined
}

/**
 * ProviderOptions type
 * @typedef {Object} ProviderOptions
 * @property {keyof typeof gasPriceOracleAddress | number} chainId - Chain ID
 * @property {string} [rpcUrl] - RPC URL
 * @property {chains.Chain['nativeCurrency']} [nativeCurrency] - Native currency
 */
type ProviderOptions = {
  chainId: keyof typeof gasPriceOracleAddress
  rpcUrl?: string | undefined
  nativeCurrency?: chains.Chain['nativeCurrency']
} | {
  chainId: number
  rpcUrl: string
  nativeCurrency?: chains.Chain['nativeCurrency']
}

/**
 * Options for all GasPriceOracle methods
 * @typedef {Object} GasPriceOracleOptions
 * @property {bigint} [blockNumber] - Block number
 * @property {BlockTag} [blockTag] - Block tag
 * @property {number} chainId - Chain ID
 * @property {string} [rpcUrl] - RPC URL
 */
export type GasPriceOracleOptions = BlockOptions & ProviderOptions

/**
 * Throws an error if fetch is not defined
 * Viem requires fetch
 * @example
* warnAboutFetch();
* @returns {void}
*/
const warnAboutFetch = () => {
  if (typeof fetch === 'undefined') {
    console.error('No fetch implementation found. Please provide a fetch polyfill. This can be done in NODE by passing in NODE_OPTIONS=--experimental-fetch or by using the isomorphic-fetch npm package')
  }
}

/**
 * Gets L2 client
 * @param {ProviderOptions} params - The provider options
 * @example
* const client = getL2Client({ chainId: 1, rpcUrl: "http://localhost:8545" });
* @returns {Promise<PublicClient>} The L2 client
*/
export const getL2Client = ({ chainId, rpcUrl, nativeCurrency }: ProviderOptions): PublicClient => {
  warnAboutFetch()
  const viemChain = Object.values(chains)?.find(chain => chain.id === chainId)
  const rpcUrls = rpcUrl ? { default: { http: [rpcUrl] }, public: { http: [rpcUrl] } } : viemChain?.rpcUrls
  if (!rpcUrls) {
    throw new Error(`No rpcUrls found for chainId ${chainId}.  Please explicitly provide one`)
  }
  return createPublicClient({
    chain: {
      id: chainId,
      name: viemChain?.name ?? 'op-chain',
      nativeCurrency: nativeCurrency ?? viemChain?.nativeCurrency ?? chains.optimism.nativeCurrency,
      network: viemChain?.network ?? 'Unknown OP Chain',
      rpcUrls,
      explorers: (viemChain as typeof chains.optimism)?.blockExplorers ?? chains.optimism.blockExplorers,
    },
    transport: http(rpcUrl ?? chains[chainId].rpcUrls.public.http[0]),
  })
}

/**
 * Get gas price Oracle contract
 * @param {ProviderOptions} params - Contains the options to connect to a blockchain provider
 * @returns {any} - Contract interface for interacting with the GasPriceOracle
 */
export const getGasPriceOracleContract = (params: ProviderOptions) => {
  return getContract({
    address: gasPriceOracleAddress['420'],
    abi: gasPriceOracleABI,
    publicClient: getL2Client(params)
  })
}

/**
 * Returns the base fee
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The base fee
 * @example
 * const baseFeeValue = await baseFee(params);
 */
export const baseFee = async (params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.baseFee(params)
}

/**
 * Returns the decimals used in the scalar
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The decimals
 * @example
 * const decimalsValue = await decimals(params);
 */
export const decimals = async (params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.decimals(params)
}

/**
 * Returns the gas price
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The gas price
 * @example
 * const gasPriceValue = await gasPrice(params);
 */
export const gasPrice = async (params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.gasPrice(params)
}

/**
 * Computes the L1 portion of the fee based on the size of the rlp encoded input
 * transaction, the current L1 base fee, and the various dynamic parameters.
 * @param {Bytes} data - Transaction data
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The L1 fee
 * @example
 * const L1FeeValue = await getL1Fee(data, params);
 */
export const getL1Fee = async (data: Bytes, params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.getL1Fee([data], params)
}

/**
 * Returns the L1 gas used
 * @param {Bytes} data - Transaction data
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The L1 gas used
 * @example
 * const L1GasUsedValue = await getL1GasUsed(data, params);
 */
export const getL1GasUsed = async (data: Bytes, params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.getL1GasUsed([data], params)
}

/**
 * Returns the L1 base fee
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The L1 base fee
 * @example
 * const L1BaseFeeValue = await l1BaseFee(params);
 */
export const l1BaseFee = async (params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.l1BaseFee(params)
}

/**
 * Returns the overhead
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The overhead
 * @example
 * const overheadValue = await overhead(params);
 */
export const overhead = async (params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.overhead(params)
}

/**
 * Returns the current fee scalar
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<bigint>} - The scalar
 * @example
 * const scalarValue = await scalar(params);
 */
export const scalar = async (params: GasPriceOracleOptions): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.scalar(params)
}

/**
 * Returns the version
 * @param {GasPriceOracleOptions} params - Block options and provider options
 * @returns {Promise<string>} - The version
 * @example
 * const versionValue = await version(params);
 */
export const version = async (params: GasPriceOracleOptions): Promise<string> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.version(params)
}