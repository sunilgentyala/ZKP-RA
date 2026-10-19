# ZKP-RA: Zero-Knowledge Proof Reasoning Anchors

**Mitigating Memory Poisoning in Autonomous Agentic DeFi**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636?logo=solidity)](contracts/Verifier.sol)
[![Circom](https://img.shields.io/badge/Circom-2.1.6-green)](circuits/reasoning_anchor.circom)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](src/agent_guardian.py)

---

## Overview

Autonomous LLM agents that execute high-value transactions in DeFi protocols face a class of attack that bypasses cryptographic key security entirely: an adversary corrupts the agent's long-term vector memory, RAG corpus, or oracle input stream, causing the agent to sign malicious transactions while believing it operates within safe parameters.

ZKP-RA addresses this by inserting a **Reasoning Anchor** into every agent-to-chain settlement path:

1. **State Commitment** — Before reasoning, the agent commits a Poseidon hash of its context window $X_t$, state vector $S_t$, and oracle inputs $I_t$ to an on-chain contract:
$$H_t = \text{Poseidon}(X_t,\, S_t,\, I_t)$$

2. **Verifiable Inference** — After producing a transaction payload $T_x$, the agent generates a Groth16 zk-SNARK (over BN254) proving that $T_x$ was derived from inputs that hash to $H_t$ and satisfy the safety policy $C$ (amount bounds, slippage limits, router whitelist):
$$\pi \leftarrow \text{Prove}(\text{pk},\; (H_t, T_x),\; (X_t, S_t, I_t, r, \sigma))$$

3. **On-Chain Settlement** — The smart contract verifies $\pi$ and executes the ERC-20 transfer atomically. Any transaction arising from poisoned inputs fails the pairing check and is rejected.

**Key metrics (measured end-to-end, real trusted setup + real on-chain deployment — see [Verification Notes](#verification-notes)):** 250 ms median proof generation (SnarkJS WASM, 100 trials), 405,659 gas total on-chain settlement (commitState + verifyAndExecute), 7,449 R1CS constraints.

---

## Repository Structure

```
ZKP-RA/
├── circuits/
│   └── reasoning_anchor.circom     # Groth16 circuit: Poseidon state commitment + policy engine
├── contracts/
│   └── Verifier.sol                # On-chain Groth16 verifier + ERC-20 settlement
├── src/
│   └── agent_guardian.py           # Async Python daemon: intercepts tool calls, drives prover
├── scripts/
│   └── compile_and_setup.sh        # Circuit compile + Phase 2 trusted setup automation
├── test/
│   └── Verifier.test.js            # Hardhat integration tests (11 passing, incl. a real Groth16 proof)
├── package.json
└── requirements.txt
```

> **Manuscript:** The companion academic paper is under review. Full text will be made available upon publication.


---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     LLM Agent Runtime                        │
│                                                              │
│  Oracle feeds ──► Context Window (Xt)                        │
│  RAG memory  ──► State Vector  (St)   ──► Poseidon ──► Ht   │
│  User intent ──► Input stream  (It)                          │
│                       │                         │            │
│                       ▼                         ▼            │
│               Policy engine C            commitState(Ht)     │
│               generates Tx              ──► chain (block b)  │
│                       │                                      │
│                       ▼                                      │
│              SnarkJS / rapidsnark                            │
│              Groth16 Prove(pk, pub, wit) ──► π               │
└───────────────────────────┬─────────────────────────────────┘
                            │ verifyAndExecute(π, Tx, nonce, ν)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              ReasoningAnchorVerifier.sol                     │
│                                                              │
│  1. Load Ht from pendingCommitments[agent][nonce]            │
│  2. Groth16 pairing check: e(A,B) = e(α,β)·e(vkx,γ)·e(C,δ) │
│  3. Enforce: amount ≤ cap, slippage ≤ 200 bps, router ∈ W   │
│  4. Mark nullifier ν (replay protection)                     │
│  5. ERC-20 safeTransfer to recipient                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Circuit Design

`circuits/reasoning_anchor.circom` arithmetizes the following statement in R1CS over the BN254 scalar field:

> *"I know private witnesses $(X_t, S_t, I_t, r, \sigma)$ such that:*
> *(1) $\text{Poseidon}(X_t \| S_t \| I_t) = H_t$*
> *(2) $T_x.\texttt{amount} \leq \text{MAX\_AMOUNT}$*
> *(3) $T_x.\texttt{slippage\_bps} \leq 200$*
> *(4) $\text{Poseidon}(r, \sigma) = T_x.\texttt{routerHash}$"*

| Parameter | Value |
|---|---|
| Proving system | Groth16 |
| Curve | BN254 (alt\_bn128) |
| Hash function | Poseidon ($t=3$, $\alpha=5$, $R_f=8$, $R_p=57$) |
| Context chunks $N_X$ | 8 field elements |
| State chunks $N_S$ | 8 field elements |
| Input chunks $N_I$ | 4 field elements |
| Total R1CS constraints | 7,449 (measured; see below) |
| Public inputs | $H_t$, recipient, amount, slippage\_bps, routerHash |

---

## Prerequisites

| Tool | Version |
|---|---|
| Node.js | 20+ (tested on 24) |
| Circom | 2.1.6+ (tested against 2.1.6 and 2.2.3) |
| SnarkJS | 0.7.4 |
| rapidsnark (optional, native prover) | 0.0.1 |
| Python | 3.10+ |
| Hardhat | 2.22+ |

```bash
npm install
pip install -r requirements.txt
```

Circom itself is not an npm package; download a platform binary from the
[circom releases page](https://github.com/iden3/circom/releases) and place it
on your `PATH` (or point `scripts/compile_and_setup.sh` at it directly).

---

## Setup

### 1. Compile the circuit and generate proving keys

```bash
bash scripts/compile_and_setup.sh
```

This downloads the Hermez BN128 Phase 1 powers-of-tau file, compiles the circuit to R1CS + WASM, runs the Phase 2 Groth16 setup, and exports the verification key.

### 2. Update verification key in the contract

After setup, extract the hex-encoded VK constants from `build/verification_key.json`
and update `VerificationKey.load()` in `contracts/Verifier.sol`. Watch for two
easy-to-miss conventions when transcribing: (a) the base field modulus `q` used
for point negation is `...696311157297823662689037894645226208583`, not the
scalar field `r` used for circuit witnesses — they're both BN254-flavored
78-digit numbers and easy to swap; (b) each G2 point's two field-extension
coefficients must be written in *reversed* order relative to the raw JSON
(`x[0] = json_x[1]`, `x[1] = json_x[0]`, and likewise for `y`) to match the
EIP-197 pairing precompile's expected input layout. `scripts/benchmark/measure_gas.cjs`
does this conversion programmatically and is the fastest way to sanity-check
a new ceremony end-to-end before hand-editing the contract.

### 3. Compile and deploy contracts

```bash
npx hardhat compile
npx hardhat run scripts/deploy.js --network <network>
```

### 4. Run the agent guardian daemon

```bash
export AGENT_PRIVATE_KEY=0x...
python src/agent_guardian.py config.json
```

**config.json:**
```json
{
  "rpc_url": "https://your-rpc-endpoint",
  "contract_address": "0xYourDeployedVerifier",
  "abi_path": "artifacts/contracts/Verifier.sol/ReasoningAnchorVerifier.json",
  "wasm_path": "build/reasoning_anchor_js/reasoning_anchor.wasm",
  "zkey_path": "build/reasoning_anchor_final.zkey",
  "rapidsnark_bin": "/usr/local/bin/rapidsnark"
}
```

---

## Testing

```bash
npx hardhat test
npx hardhat coverage
```

---

## Gas Costs

Measured via `npm run benchmark:gas` (Hardhat local network, a real Groth16
proof against the dev ceremony's verification key, full `commitState` →
`verifyAndExecute` flow including the ERC-20 transfer):

| Call | Gas (measured) |
|---|---|
| `commitState` | 73,022 |
| `verifyAndExecute` (pairing check + policy checks + ERC-20 transfer) | 332,637 |
| **Total per settled transaction** | **405,659** |

This is an aggregate on-chain measurement, not a hand-derived per-opcode
estimate — run `npm run benchmark:gas` yourself to reproduce it or profile a
finer breakdown with `hardhat-gas-reporter`.

---

## Security Properties

| Property | Guarantee |
|---|---|
| **Completeness** | An honest agent with valid witnesses always produces an accepted proof |
| **Soundness** | Under $q$-SDH on BN254 and Poseidon collision resistance, no adversary can pass a poisoned-input transaction |
| **Zero-Knowledge** | The proof reveals nothing about $X_t$, $S_t$, $I_t$, the router address, or the proving salt |

---

## Proof Generation Benchmarks

Original 20-trial run (`npm run benchmark:input && npm run benchmark:proof`): median 224 ms, min 201 ms, max 423 ms.

Re-measured 2026-10-18 with 100 `snarkjs.groth16.fullProve` trials per circuit (witness generation + proving combined, own single-contributor 2^15 ptau, nothing else running):

| Circuit | Chunks | Constraints | Median | p95 | p99 | Min | Max |
|---|---|---|---|---|---|---|---|
| Commit 168237f (paper) | 20 | 7,449 | 250 ms | 324 ms | 349 ms | 225 ms | 542 ms |
| HEAD (with range checks, 3335767) | 20 | 7,717 | 253 ms | 283 ms | 298 ms | 228 ms | 317 ms |
| 2x chunks | 40 | 13,499 | 439 ms | 524 ms | 564 ms | 402 ms | 582 ms |
| 4x chunks | 80 | 25,599 | 721 ms | 814 ms | 932 ms | 677 ms | 973 ms |

The circuit commits a fixed 20 chunks of 31 bytes (8 context, 8 state, 4 oracle input), not an entire context window; cost grows linearly with chunk count (about 302 constraints per added chunk). The 2x/4x circuits are the same template with `nCtx()/nState()/nInput()` scaled. Scripts: `scripts/benchmark/scale_bench.cjs`, results in `scripts/benchmark/results/`.

Tamper checks (`scripts/benchmark/tamper_test.cjs`, output in `results/`): changing any one of the 5 public inputs or the proof point A makes verification fail; poisoning a context, state or input chunk, or exceeding the amount cap, makes proof generation fail.

rapidsnark (native C++) was not benchmarked; no claim is made about its speed.

---|---|---|---|
| SnarkJS (WASM) | 224 ms | 201 ms | 423 ms |
| rapidsnark (native C++) | not benchmarked in this repo | — | — |

Benchmarked on an AMD Ryzen AI 7 350 (16 threads), Node.js v24.16.0, Windows.
rapidsnark requires a native C++ build toolchain not exercised here; expect a
meaningful additional speedup consistent with published rapidsnark vs. SnarkJS-WASM
comparisons, but treat any specific number as unverified until benchmarked directly.

---

## References

1. B.J. Chen et al., "ZKML," EuroSys 2024. DOI: [10.1145/3627703.3650088](https://doi.org/10.1145/3627703.3650088)
2. J. Groth, "On the Size of Pairing-Based Non-interactive Arguments," EUROCRYPT 2016. DOI: [10.1007/978-3-662-49896-5_11](https://doi.org/10.1007/978-3-662-49896-5_11)
3. L. Grassi et al., "Poseidon Hash," USENIX Security 2021. [usenix.org](https://www.usenix.org/conference/usenixsecurity21/presentation/grassi)
4. K. Greshake et al., "Indirect Prompt Injection," AISec@CCS 2023. DOI: [10.1145/3605764.3623985](https://doi.org/10.1145/3605764.3623985)
5. S. Lee et al., "vCNN," IEEE TDSC 2024. DOI: [10.1109/TDSC.2023.3348760](https://doi.org/10.1109/TDSC.2023.3348760)
6. K. Wang et al., "VeriLLM: A Lightweight Framework for Publicly Verifiable Decentralized Inference," arXiv:2509.24257, 2025. DOI: [10.48550/arXiv.2509.24257](https://doi.org/10.48550/arXiv.2509.24257)
7. L. Zhou et al., "SoK: DeFi Attacks," IEEE S&P 2023. DOI: [10.1109/SP46215.2023.10179435](https://doi.org/10.1109/SP46215.2023.10179435)
8. W. Zou, R. Geng, B. Wang, and J. Jia, "PoisonedRAG," arXiv:2402.07867, 2024. DOI: [10.48550/arXiv.2402.07867](https://doi.org/10.48550/arXiv.2402.07867)
9. A. Gabizon et al., "PLONK," IACR ePrint 2019/953. [eprint.iacr.org](https://eprint.iacr.org/2019/953)
10. Z. Peng et al., "ZK Survey," AI Review 2026. DOI: [10.1007/s10462-026-11557-y](https://doi.org/10.1007/s10462-026-11557-y)
11. M. Pratiwi and Y.-H. Choi, "DeFiTrace," ACM Trans. Privacy and Security, vol. 29, no. 3, 2026. DOI: [10.1145/3817054](https://doi.org/10.1145/3817054)
12. E. Ben-Sasson et al., "STARKs," IACR ePrint 2018/046. [eprint.iacr.org](https://eprint.iacr.org/2018/046)
13. N. Romandini, C. Mazzocca, K. Otsuki, and R. Montanari, "SoK: Security and Privacy of AI Agents for Blockchain," arXiv:2509.07131, accepted BCCA 2025. DOI: [10.48550/arXiv.2509.07131](https://doi.org/10.48550/arXiv.2509.07131)
14. Y. Xie et al., "DeFort," ISSTA 2024. DOI: [10.1145/3650212.3652137](https://doi.org/10.1145/3650212.3652137)
15. S.K. Mudusu and S. Gentyala, "Zero-Trust Data Pipelines for AI Systems: A Framework for Secure, Verifiable, and Auditable Data Engineering," JRTCSE, vol. 14, no. 2.2, 2026. DOI: [10.70589/JRTCSE.2026.14.2.2](https://doi.org/10.70589/JRTCSE.2026.14.2.2)

---

## Verification Notes

This repository was end-to-end verified (circuit compiled, real trusted setup
run, a real proof generated and checked both off-chain and on-chain, full
Hardhat test suite passing) as part of preparing the companion manuscript.
That pass found and fixed several bugs that meant nothing here had actually
been compiled or run before:

- The circuit used a top-level `var` declaration pattern invalid in circom
  2.x; it had never successfully compiled. Fixed by moving the constants into
  `function`s.
- The on-chain pairing check used `vk.beta` instead of `proof.B` in one term
  of the Groth16 equation — the proof's own B point was never actually
  checked. Fixed.
- The pairing equation negated `vk_x` and `proof.C` in addition to `proof.A`;
  only `proof.A` should be negated. Fixed.
- The router whitelist stored entries by address but looked them up via a
  bytes32→address reinterpretation that could never match a real address;
  separately, the circuit commits the router via Poseidon while the contract
  expected keccak256. Unified to a single hash-keyed whitelist.
- `VerificationKey.load()` held literal placeholder values. Replaced with a
  real ceremony's output (dev/benchmark ceremony — regenerate before any
  production deployment).
- The Python agent's `verify_and_execute` recomputed the router hash via
  keccak256 while the proof committed to a Poseidon-based value, and its
  nullifier derivation hashed only 2 of the 4 required fields. Both fixed.
- No `hardhat.config`, no `MockERC20` contract, and no `tsconfig.json`
  existed, so nothing could have been compiled or tested as shipped. Added.

All numbers reported above and in the companion paper are real measurements
taken after these fixes, not estimates. Reproduce them with
`npm run benchmark:input && npm run benchmark:proof` (proof generation) and
`npm run benchmark:gas` (on-chain settlement cost).

---

## Author

**Sunil Gentyala** — Lead Cybersecurity and AI Security Consultant, HCL America Inc.
IEEE Senior Member · sunil.gentyala@ieee.org · [github.com/sunilgentyala](https://github.com/sunilgentyala)

---

## How to Cite

The companion paper is under review. Until it is published, please cite the software:

```bibtex
@software{gentyala2026zkpra,
  author    = {Gentyala, Sunil},
  title     = {ZKP-RA: Zero-Knowledge Proof Reasoning Anchors},
  year      = {2026},
  url       = {https://github.com/sunilgentyala/ZKP-RA}
}
```

Machine-readable metadata is in [`CITATION.cff`](CITATION.cff); GitHub shows it under "Cite this repository".

---

## License

MIT License. See [LICENSE](LICENSE) for details.
