import { vi, test, expect, beforeEach } from 'vitest'
import { formatEther } from 'viem/utils'
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
} from './estimateFees'

// https://optimistic.etherscan.io/tx/0xceb34708f1de2ea2336dbdd81ca2cb7b12ec2ab6adc86a0d7d81c8c4416f81bb
const data =
  '0x5c19a95c00000000000000000000000046abfe1c972fca43766d6ad70e1c1df72f4bb4d1'

const chainConfig = {
  chainId: 10,
  rpcUrl: process.env.VITE_L2_RPC_URL ?? 'https://mainnet.optimism.io',
} as const

const blockConfig = {
  blockNumber: BigInt(106889079),
}

const params = { ...chainConfig, ...blockConfig }

beforeEach(() => {
  vi.resetAllMocks()
})

test('baseFee should return the correct result', async () => {
  expect(await baseFee(params)).toMatchInlineSnapshot('65n')
})

test('decimals should return the correct result', async () => {
  expect(await decimals(params)).toMatchInlineSnapshot('6n')
})

test('gasPrice should return the correct result', async () => {
  expect(await gasPrice(params)).toMatchInlineSnapshot('65n')
})

test('getL1Fee should return the correct result', async () => {
  expect(await getL1Fee(data, params)).toMatchInlineSnapshot('15130316373984n')
})

test('getL1GasUsed should return the correct result', async () => {
  expect(await getL1GasUsed(data, params)).toMatchInlineSnapshot('1708n')
})

test('l1BaseFee should return the correct result', async () => {
  expect(await l1BaseFee(params)).toMatchInlineSnapshot('12951022000n')
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

test('estimateFees should return correct fees', async () => {
  const data =
    '0xd1e16f0a603acf1f8150e020434b096e408bafa429a7134fbdad2ae82a9b2b882bfcf5fe174162cf4b3d5f2ab46ff6433792fc99885d55ce0972d982583cc1e11b64b1d8d50121c0497642000000000000000000000000000000000000060a2c8052ed420000000000000000000000000000000000004234002c8052edba12222222228d8ba445958a75a0704d566bf2c84200000000000000000000000000000000000006420000000000000000000000000000000000004239965c9dab5448482cf7e002f583c812ceb53046000100000000000000000003'
  const account = '0xe371815c5f8a4f9acd1576879de288acd81269f1'
  const to = '0xe35f24470730f5a488da9721548c1ab0b65b53d5'
  const fees = await estimateFees({ ...params, to, data, account })
  expect(fees).toMatchInlineSnapshot('33237088573005n')
  expect(formatEther(fees)).toMatchInlineSnapshot('"0.000033237088573005"')
})
