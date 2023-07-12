# GasEstimation Documentation

This code provides a set of utilities for interacting with the [GasPriceOracle](../contracts-bedrock/contracts/l2/GasPriceOracle.sol) contract on Optimism, an Ethereum Layer 2 solution. This module enables you to fetch various data, such as base fee, decimals, gas price, and more from the GasPriceOracle contract. This information can be particularly useful for calculating transaction costs.

The GasPriceOracle is [deployed to Optimism](https://optimistic.etherscan.io/address/0x420000000000000000000000000000000000000F) and other OP chains at a predeployed address of `0x420000000000000000000000000000000000000F`

For more detailed information about gas fees on Optimism's Layer 2, you can visit their [official documentation](https://community.optimism.io/docs/developers/build/transaction-fees/#the-l2-execution-fee).

## Quick Start:
In this example, we're calculating the total gas cost for a given transaction data along with l1 and l2 gas costs.

```typescript
import { baseFee, getL1Fee, getL1GasUsed, gasPrice, getL2Client } from '@eth-optimism/contracts-ts'

const transactionData = '0x5c19a95c00000000000000000000000046abfe1c972fca43766d6ad70e1c1df72f4bb4d1'

const l2Client = getL2Client({ chainId: 10 })
const l2GasEstimate = await l2Client.estimateGas({
  data: transactionData,
  account: '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266',
  to: '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
})
const l1Gas = await getL1GasUsed(transactionData, { chainId: 10 })
const totalGas = l1Gas + l2Gas
```

## Types
### `BlockOptions`
Optional parameters for choosing a specific block to query.

```typescript
type BlockOptions = {
  blockNumber?: bigint
  blockTag?: BlockTag
}
```

### `GasPriceOracleOptions`
Options for all GasPriceOracle methods. Combines both `BlockOptions` and `ProviderOptions`.

```typescript
export type GasPriceOracleOptions = BlockOptions & ProviderOptions
```

### `ProviderOptions`
Options to connect to a blockchain provider.

```typescript
type ProviderOptions = {
  chainId: keyof typeof gasPriceOracleAddress
  rpcUrl?: string
  nativeCurrency?: chains.Chain['nativeCurrency']
} | {
  chainId: number
  rpcUrl: string
  nativeCurrency?: chains.Chain['nativeCurrency']
}
```

## Functions

### `getL2Client`
This function is used to generate an L2 client for a specific chain.

```typescript
/**
 * Gets L2 client
 * @param {ProviderOptions} params - The provider options
 * @example
 * const client = getL2Client({ chainId: 1, rpcUrl: "http://localhost:8545" });
 * @returns {Promise<PublicClient>} The L2 client
 */
function getL2Client({ chainId, rpcUrl, nativeCurrency }: ProviderOptions): Promise<PublicClient>
```

### `getGasPriceOracleContract`
This function is used to get a handle on the GasPriceOracle contract which can be used for subsequent calls.

```typescript
/**
 * Get gas price Oracle contract
 * @param {ProviderOptions} params - Contains the options to connect to a blockchain provider
 * @returns {any} - Contract interface for interacting with the GasPriceOracle
 */
function getGasPriceOracleContract(params: ProviderOptions): any
```


### `baseFee`
Returns the base fee.
```typescript
function baseFee(params: GasPriceOracleOptions): Promise<bigint>
```

### `decimals`
Returns the decimals.
```typescript
function decimals(params: GasPriceOracleOptions): Promise<bigint>
```

### `gasPrice`
Returns the gas price.
```typescript
function gasPrice(params: GasPriceOracleOptions): Promise<bigint>
```

### `getL1Fee`
Returns the L1 fee.
```typescript
function getL1Fee(data: Bytes, params: GasPriceOracleOptions): Promise<bigint>
```

### `getL1GasUsed`
Returns the L1 gas used.
```typescript
function getL1GasUsed(data: Bytes, params: GasPriceOracleOptions): Promise<bigint>
```

### `l1BaseFee`
Returns the L1 base fee.
```typescript
function l1BaseFee(params: GasPriceOracleOptions): Promise<bigint>
```

### `overhead`
Returns the overhead.
```typescript
function overhead(params: GasPriceOracleOptions): Promise<bigint>
```

### `scalar`
Returns the scalar.
```typescript
function scalar(params: GasPriceOracleOptions): Promise<bigint>
```

### `version`
Returns the version.
```typescript
function version(params: GasPriceOracleOptions): Promise<string>
```

Please note, for each function you need to pass `GasPriceOracleOptions` object as parameter.
