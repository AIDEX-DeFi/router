# AIDEX Router

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](./LICENSE) ![Solidity](https://img.shields.io/badge/Solidity-0.8.35-blue)

The AIDEX Router is the on-chain execution layer of the AIDEX DEX aggregator — a single contract that chains swaps across multiple liquidity pools and exchanges into one transaction.

AIDEX is built around the gap between an agent's decision and the moment its signed transaction reaches the network — the window in which the price moves against the trader. Off-chain, a millisecond-latency HTTP API picks the optimal route. On-chain, this router settles that route without burning the latency advantage on gas: the trader specifies the input and output tokens, and the router executes the full multi-hop sequence in a single call.

Supported protocols:
- Uniswap V2, V3, V4 and forks
- Balancer V1 and V2

To minimise gas on every swap, the entire runtime is hand-written in EVM assembly (Yul) inside the fallback function, bypassing the Solidity dispatcher and ABI-decoding overhead.

Learn more at [ai-dex.io](https://ai-dex.io/)

## Live on Mainnet

Router contract: [`0x1208d02aac7d247eb79b71ce23c792441457e7b3`](https://etherscan.io/address/0x1208d02aac7d247eb79b71ce23c792441457e7b3) · [source](./contracts/AiDexRouter.sol)

## Project

This contract is one component of AIDEX. The wider project lives at [github.com/AIDEX-DeFi](https://github.com/AIDEX-DeFi):

- **Documentation** — AIDEX Agents API reference, OpenAPI spec, playground
- **skills** — AIDEX skill for AI agents (OpenClaw): swap, quote, balance, verify
- **genesis-key** — ERC-721 that grants its holder execution priority inside AIDEX

## License

MIT
