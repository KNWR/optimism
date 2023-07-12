import { vi, test, expect, beforeEach } from 'vitest'
import { baseFee, decimals, gasPrice, getL1Fee, getL1GasUsed, l1BaseFee, overhead, scalar, version } from './estimateGas'

// https://optimistic.etherscan.io/tx/0xceb34708f1de2ea2336dbdd81ca2cb7b12ec2ab6adc86a0d7d81c8c4416f81bb
const data = '0x5c19a95c00000000000000000000000046abfe1c972fca43766d6ad70e1c1df72f4bb4d1'

const chainConfig =
  {
    chainId: 10,
    rpcUrl: process.env.VITE_L2_RPC_URL ?? 'https://mainnet.optimism.io',
  } as const

const blockConfig = {
  blockNumber: BigInt(106773236),
}

const params = { ...chainConfig, ...blockConfig };

beforeEach(() => {
  vi.resetAllMocks()
})

test('baseFee should return the correct result', async () => {
  expect(await baseFee(params)).toMatchInlineSnapshot('64n')
})

test('decimals should return the correct result', async () => {
  expect(await decimals(params)).toMatchInlineSnapshot('6n')
})

test('gasPrice should return the correct result', async () => {
  expect(await gasPrice(params)).toMatchInlineSnapshot('64n')
})

test('getL1Fee should return the correct result', async () => {
  expect(await getL1Fee(data, params)).toMatchInlineSnapshot('15860541911298n')
})

test('getL1GasUsed should return the correct result', async () => {
  expect(await getL1GasUsed(data, params)).toMatchInlineSnapshot('1708n')
})

test('l1BaseFee should return the correct result', async () => {
  expect(await l1BaseFee(params)).toMatchInlineSnapshot('13576069538n')
})

test('overhead should return the correct result', async () => {
  expect(await overhead(params)).toMatchInlineSnapshot('188n')
})

test('scalar should return the correct result', async () => {
  expect(await scalar(params)).toMatchInlineSnapshot('684000n')
})

test('version should return the correct result', async () => {
  expect(await version(params)).toMatchInlineSnapshot('"1.0.0"')
})

