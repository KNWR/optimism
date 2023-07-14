import {
  gasPriceOracleABI,
  gasPriceOracleAddress,
} from '@eth-optimism/contracts-ts'
import {
  getContract,
  createPublicClient,
  http,
  BlockTag,
  Address,
  EstimateGasParameters,
} from 'viem'
import * as chains from 'viem/chains'
import { PublicClient } from 'wagmi'

/**
 * Bytes type representing a hex string with a 0x prefix
 * @typedef {`0x${string}`} Bytes
 */
export type Bytes = `0x${string}`

/**
 * Options to query a specific block
 */
type BlockOptions = {
  /**
   * Block number to query from
   */
  blockNumber?: bigint
  /**
   * Block tag to query from
   */
  blockTag?: BlockTag
}

/**
 * ProviderOptions type
 * @typedef {Object} ProviderOptions
 * @property {keyof typeof gasPriceOracleAddress | number} chainId - Chain ID
 * @property {string} [rpcUrl] - RPC URL. If not provided the provider will attempt to use public RPC URLs for the chain
 * @property {chains.Chain['nativeCurrency']} [nativeCurrency] - Native currency. Defaults to ETH
 */
type ProviderOptions =
  | {
    chainId: keyof typeof gasPriceOracleAddress
    rpcUrl?: string
    nativeCurrency?: chains.Chain['nativeCurrency']
  }
  | {
    chainId: number
    rpcUrl: string
    nativeCurrency?: chains.Chain['nativeCurrency']
  }

/**
 * Options for all GasPriceOracle methods
 */
export type GasPriceOracleOptions = BlockOptions & ProviderOptions

/**
 * Throws an error if fetch is not defined
 * Viem requires fetch
 */
const validateFetch = () => {
  if (typeof fetch === 'undefined') {
    throw new Error(
      'No fetch implementation found. Please provide a fetch polyfill. This can be done in NODE by passing in NODE_OPTIONS=--experimental-fetch or by using the isomorphic-fetch npm package'
    )
  }
}

/**
 * Gets L2 client
 * @example
 * const client = getL2Client({ chainId: 1, rpcUrl: "http://localhost:8545" });
 */
export const getL2Client = ({
  chainId,
  rpcUrl,
  nativeCurrency,
}: ProviderOptions): PublicClient => {
  validateFetch()
  const viemChain = Object.values(chains)?.find((chain) => chain.id === chainId)
  const rpcUrls = rpcUrl
    ? { default: { http: [rpcUrl] }, public: { http: [rpcUrl] } }
    : viemChain?.rpcUrls
  if (!rpcUrls) {
    throw new Error(
      `No rpcUrls found for chainId ${chainId}.  Please explicitly provide one`
    )
  }
  return createPublicClient({
    chain: {
      id: chainId,
      name: viemChain?.name ?? 'op-chain',
      nativeCurrency:
        nativeCurrency ??
        viemChain?.nativeCurrency ??
        chains.optimism.nativeCurrency,
      network: viemChain?.network ?? 'Unknown OP Chain',
      rpcUrls,
      explorers:
        (viemChain as typeof chains.optimism)?.blockExplorers ??
        chains.optimism.blockExplorers,
    },
    transport: http(rpcUrl ?? chains[chainId].rpcUrls.public.http[0]),
  })
}

/**
 * Get gas price Oracle contract
 */
export const getGasPriceOracleContract = (params: ProviderOptions) => {
  return getContract({
    address: gasPriceOracleAddress['420'],
    abi: gasPriceOracleABI,
    publicClient: getL2Client(params),
  })
}

/**
 * Returns the base fee
 * @returns {Promise<bigint>} - The base fee
 * @example
 * const baseFeeValue = await baseFee(params);
 */
export const baseFee = async (
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.baseFee(params)
}

/**
 * Returns the decimals used in the scalar
 * @example
 * const decimalsValue = await decimals(params);
 */
export const decimals = async (
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.decimals(params)
}

/**
 * Returns the gas price
 * @example
 * const gasPriceValue = await gasPrice(params);
 */
export const gasPrice = async (
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.gasPrice(params)
}

/**
 * Computes the L1 portion of the fee based on the size of the rlp encoded input
 * transaction, the current L1 base fee, and the various dynamic parameters.
 * @example
 * const L1FeeValue = await getL1Fee(data, params);
 */
export const getL1Fee = async (
  data: Bytes,
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.getL1Fee([data], params)
}

/**
 * Returns the L1 gas used
 * @example
 */
export const getL1GasUsed = async (
  /**
   * The transaction call data as a 0x-prefixed hex string
   */
  data: Bytes,
  /**
   * Optional lock options and provider options
   */
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.getL1GasUsed([data], params)
}

/**
 * Returns the L1 base fee
 * @example
 * const L1BaseFeeValue = await l1BaseFee(params);
 */
export const l1BaseFee = async (
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.l1BaseFee(params)
}

/**
 * Returns the overhead
 * @example
 * const overheadValue = await overhead(params);
 */
export const overhead = async (
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.overhead(params)
}

/**
 * Returns the current fee scalar
 * @example
 * const scalarValue = await scalar(params);
 */
export const scalar = async (
  params: GasPriceOracleOptions
): Promise<bigint> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.scalar(params)
}

/**
 * Returns the version
 * @example
 * const versionValue = await version(params);
 */
export const version = async (
  params: GasPriceOracleOptions
): Promise<string> => {
  const contract = getGasPriceOracleContract(params)
  return contract.read.version(params)
}

export type EstimateFeeParams = {
  /**
   * The transaction call data as a 0x-prefixed hex string
   */
  data: Bytes
  /**
   * The address of the account that will be sending the transaction
   */
  account: Address
} & GasPriceOracleOptions &
  Omit<EstimateGasParameters, 'data' | 'account'>

/**
 * Estimates gas for an L2 transaction including the l1 fee
 */
export const estimateFees = async ({
  blockNumber,
  data,
  chainId,
  rpcUrl,
  nativeCurrency,
  blockTag,
  ...viemParams
}: EstimateFeeParams) => {
  const provider = getL2Client({ chainId, rpcUrl: rpcUrl as string, nativeCurrency })
  const [l2Fee, l1Fee] = await Promise.all([
    provider.estimateGas({
      // viem has really strict types and this as undefined is a hack to get around it
      blockNumber: blockNumber as undefined,
      blockTag,
      data,
      ...viemParams
    }),
    getL1Fee(data, {
      blockNumber,
      chainId,
      rpcUrl: rpcUrl as string,
      nativeCurrency,
      blockTag,
    }),
  ])
  return l1Fee + l2Fee
}
