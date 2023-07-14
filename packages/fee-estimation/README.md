# GasEstimation Documentation

## Why

Gas estimation on OP-chains has both an l2 and l1 component. By default tools such as Viem, Wagmi, Ethers, and Web3.js do not support the l1 component. They will support this soon but in meantime this library can help estimate fees for transactions.
As these tools add support for gas estimation natively this README will be updated with framework specific instructions.

## High level

- The l2 contract that can estimate l1Fees is called [GasPriceOracle](../contracts-bedrock/contracts/l2/GasPriceOracle.sol) contract. This library provides utils for interacting with it at a high level.
- The GasPriceOracle is [deployed to Optimism](https://optimistic.etherscan.io/address/0x420000000000000000000000000000000000000F) and other OP chains at a predeployed address of `0x420000000000000000000000000000000000000F`

For more detailed information about gas fees on Optimism's Layer 2, you can visit their [official documentation](https://community.optimism.io/docs/developers/build/transaction-fees/#the-l2-execution-fee).

## Installation:

```bash
pnpm i @eth-optimism/fee-estimation
```

```bash
npm i @eth-optimism/fee-estimation
```

```
yarn add @eth-optimism/fee-estimation
```

## Importing the Gas Fee Estimator

To use the Gas Fee Estimator in your file, import it:

```typescript
import {
  baseFee,
  decimals,
  estimateFees,
  gasPrice,
  getL1Fee,
  getL1GasUsed,
  l1BaseFee,
  overhead,
  scalar,
  version,
} from '@eth-optimism/fee-estimator'
```

## Usage

### Provider Options

Provider options are required for most function calls. They specify the chain and RPC URL for fetching data. They can be defined as follows:

```typescript
const chainConfig = {
  chainId: 10,
  rpcUrl: 'https://mainnet.optimism.io',
}
```

### Block Options

Block options specify the block from which to retrieve data. They can be defined as follows:

```typescript
const blockConfig = {
  blockNumber: BigInt(106889079),
}
```

These options can then be combined to form the parameters for function calls:

```typescript
const params = { ...chainConfig, ...blockConfig }
```

### Retrieving Base Fee

To retrieve the base fee:

```typescript
const baseFeeValue = await baseFee(params)
```

### Retrieving Gas Price

To retrieve the gas price:

```typescript
const gasPriceValue = await gasPrice(params)
```

### Estimating Fees

To estimate fees for a transaction:

```typescript
const data = '0xd1e16f0a603ac...' // transaction data
const account = '0xe371815c5f8a4f9acd1576879de288acd81269f1'
const to = '0xe35f24470730f5a488da9721548c1ab0b65b53d5'
const fees = await estimateFees({ ...params, to, data, account })
```

This will return the estimated gas fee for the specified transaction.

## Tests

Tests for the library are included in the `test` directory. You can run them using your test runner of choice. The provided tests use [Vitest](https://vitest.dev/).

## Conclusion

The Gas Fee Estimator is a valuable tool for any project that interacts with Ethereum L2 transactions. It provides reliable gas fee estimates to ensure transactions are processed efficiently and economically.
