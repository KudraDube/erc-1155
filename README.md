# TieredPass1155

An ERC-1155 membership pass with several tiers (for example Gold and Silver) that users mint with a voucher signed by a backend. Each tier can have its own supply cap.

Think of a members' club. The backend is the receptionist who signs a slip saying "this person may collect 1 Gold pass, slip number 17, valid until Friday". The contract is the door. It checks that the slip is signed by the receptionist and is not expired or already used before it hands over the pass.

## Why I built it

Signed vouchers are how most real NFT and pass systems let a backend decide who may mint without paying gas for every approval. I wanted to understand every field that goes into the signature and what attack each one blocks. ERC-1155 also taught me how one contract holds many token types at once.

## Status

| Item | State |
|---|---|
| Contract | Complete, patched with the Contracts Pack fixes |
| Tests | 42 passing (unit, signature attacks, supply cap, receiver hook, fuzz, invariant) |
| Audit | None. This is a learning project, **do not deploy with real funds** |

## How it works

| Piece | Job |
|---|---|
| `mintWithSignature` | User submits tier, amount, nonce, deadline and the backend's signature |
| Signed hash | Caller, tier, amount, nonce, deadline, contract address and chain id |
| `SIGNER_ROLE` | Only signatures from an address with this role are accepted |
| `usedNonces` | Marks each voucher as spent so it cannot be replayed |
| `maxSupply` and `totalMinted` | Per-tier cap and a lifetime count of what has been minted |
| `_update` override | Every mint, burn and transfer passes through it, so the cap is enforced in one place |
| Pausable | The admin can stop new minting |

## What I patched and why

- **`totalMinted` now increases inside `_update`.** The original only counted in `mintWithSignature`. The `_update` cap guard reads that same number. A future mint function that forgot the check would also forget the increment, so the guard would see nothing and let the cap be exceeded. Counting at the lowest level means every mint path is counted and capped automatically. Tests use a harness contract that mints without any checks to prove it.
- **A signature deadline.** Without an expiry a voucher stays valid forever. The deadline is part of the signed data so a caller cannot extend it.

Four of the tests fail against the original accounting and pass against the patched one.

## Design decisions

- **The signature covers the caller, the contract and the chain.** A voucher cannot be stolen by another wallet or reused on another contract or chain.
- **The nonce is marked used before `_mint`.** The mint calls the receiver's hook, which is a reentrancy door. A test shows a hook that tries to replay the voucher is rejected.
- **A failed mint does not burn the nonce**, because everything reverts together.
- **Roles instead of a single owner.** The admin and the signer are different roles, so a leaked signing key cannot change caps or unpause.
- **Only fixed-size values are packed into the hash**, so two different requests cannot produce the same bytes.

## Known limitations

- **Tiers are uncapped until the admin sets a cap.** A compromised signer could mint unlimited passes in an uncapped tier.
- **One admin address holds all admin power.** It can pause, change caps and grant signers. A real deployment would put it behind a multisig and a timelock.
- **Pause stops minting only.** Holders can still transfer. A test documents this.
- **The backend must never reuse a nonce for a different request**, and it decides how many vouchers one person can get. The contract only enforces one use per voucher.
- **`totalMinted` is a lifetime count.** Burning does not free up supply.
- **Minting to a contract requires it to implement the ERC-1155 receiver hook.** Otherwise the mint reverts.
- **Not audited.**

## Tests

`test/TieredPass1155.t.sol`, 42 tests:

- roles, URI and interface support
- every admin function with access control
- the happy path with events
- signature attacks: wrong key, revoked signer, changed tier, amount, nonce, deadline, caller, contract or chain, malformed bytes, replay
- deadline at exactly the limit, one second late and fuzzed
- supply cap rules per tier and raising a cap
- the `_update` guard through a harness that mints without checks, including a batch mint
- a receiver contract with no hook and a hook that tries to replay the voucher
- fuzz tests for caps, signed amounts and expiry
- 2 invariants after random mints, cap changes and transfers

## Run it

```bash
forge install OpenZeppelin/openzeppelin-contracts foundry-rs/forge-std
forge test
```

## What I practised

- building and verifying an ECDSA voucher scheme and signing in tests with `vm.sign`
- replay protection with nonces and domain separation with the contract address and chain id
- deadlines inside signed data
- overriding `_update` and using multiple inheritance (ERC1155 and AccessControl)
- testing a guard against a future mistake with a harness contract
- reading a weakness in my own contract from the Contracts Pack and fixing it with a failing test first

## Where this is going

I am a WeThinkCode blockchain graduate building towards a junior Solidity or Web3 role. This repository is one of a set (SimpleDEX, EthVault, MultiSigWallet, P2PEscrow, StakingRewards, TieredPass1155) where each contract comes with tests I can explain line by line.
