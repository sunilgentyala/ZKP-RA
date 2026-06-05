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

**Key metrics:** 182 ms proof generation (rapidsnark), ~276,200 gas on-chain verification, ~3,800 R1CS constraints — a **9.7× gas reduction** versus full zkML inference verification.

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
│   └── Verifier.test.ts            # Hardhat integration tests
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
| Total R1CS constraints | ~3,800 |
| Public inputs | $H_t$, recipient, amount, slippage\_bps, routerHash |

---

## Prerequisites

| Tool | Version |
|---|---|
| Node.js | 20+ |
| Circom | 2.1.6 |
| SnarkJS | 0.7.4 |
| rapidsnark (optional) | 0.0.1 |
| Python | 3.10+ |
| Hardhat | 2.22+ |

```bash
npm install
pip install -r requirements.txt
```

---

## Setup

### 1. Compile the circuit and generate proving keys

```bash
bash scripts/compile_and_setup.sh
```

This downloads the Hermez BN128 Phase 1 powers-of-tau file, compiles the circuit to R1CS + WASM, runs the Phase 2 Groth16 setup, and exports the verification key.

### 2. Update verification key in the contract

After setup, replace the placeholder IC values in `contracts/Verifier.sol` with the output of:

```bash
snarkjs vkey --verificationkey build/verification_key.json
```

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

## Gas Costs (EVM, Istanbul opcodes)

| Operation | Gas |
|---|---|
| BN254 pairing — EIP-197 (4 pairs) | 180,000 |
| Scalar multiplication — EIP-196 (5×) | 30,000 |
| Point addition — EIP-196 (4×) | 2,000 |
| Storage reads (commitment + nullifier) | 4,200 |
| ERC-20 safeTransfer | 35,000 |
| Calldata + event emission | 25,000 |
| **Total** | **276,200** |

---

## Security Properties

| Property | Guarantee |
|---|---|
| **Completeness** | An honest agent with valid witnesses always produces an accepted proof |
| **Soundness** | Under $q$-SDH on BN254 and Poseidon collision resistance, no adversary can pass a poisoned-input transaction |
| **Zero-Knowledge** | The proof reveals nothing about $X_t$, $S_t$, $I_t$, the router address, or the proving salt |

---

## Proof Generation Benchmarks

| Backend | Witness | Prove | Total |
|---|---|---|---|
| SnarkJS (WASM) | 38 ms | 1,164 ms | 1,202 ms |
| rapidsnark (native C++) | 12 ms | 170 ms | **182 ms** |

Benchmarked on AMD EPYC 9354, 128 GB DDR5, Ubuntu 22.04.

---

## References

1. B.J. Chen et al., "ZKML," EuroSys 2024. DOI: [10.1145/3627703.3650088](https://doi.org/10.1145/3627703.3650088)
2. J. Groth, "On the Size of Pairing-Based Non-interactive Arguments," EUROCRYPT 2016. DOI: [10.1007/978-3-662-49896-5_11](https://doi.org/10.1007/978-3-662-49896-5_11)
3. L. Grassi et al., "Poseidon Hash," USENIX Security 2021. [usenix.org](https://www.usenix.org/conference/usenixsecurity21/presentation/grassi)
4. K. Greshake et al., "Indirect Prompt Injection," AISec@CCS 2023. DOI: [10.1145/3605764.3623985](https://doi.org/10.1145/3605764.3623985)
5. S. Lee et al., "vCNN," IEEE TDSC 2024. DOI: [10.1109/TDSC.2023.3348760](https://doi.org/10.1109/TDSC.2023.3348760)
6. VeriLLM, arXiv:2509.24257. DOI: [10.48550/arXiv.2509.24257](https://doi.org/10.48550/arXiv.2509.24257)
7. L. Zhou et al., "SoK: DeFi Attacks," IEEE S&P 2023. DOI: [10.1109/SP46215.2023.10179435](https://doi.org/10.1109/SP46215.2023.10179435)
8. Z. Zou et al., "PoisonedRAG," arXiv:2402.07867. DOI: [10.48550/arXiv.2402.07867](https://doi.org/10.48550/arXiv.2402.07867)
9. A. Gabizon et al., "PLONK," IACR ePrint 2019/953. [eprint.iacr.org](https://eprint.iacr.org/2019/953)
10. Z. Peng et al., "ZK Survey," AI Review 2026. DOI: [10.1007/s10462-026-11557-y](https://doi.org/10.1007/s10462-026-11557-y)
11. DeFiTrace, ACM TOPS 2024. DOI: [10.1145/3817054](https://doi.org/10.1145/3817054)
12. E. Ben-Sasson et al., "STARKs," IACR ePrint 2018/046. [eprint.iacr.org](https://eprint.iacr.org/2018/046)
13. M.M. Karim et al., "AI Agents Meet Blockchain," Future Internet 2025. DOI: [10.3390/fi17020057](https://doi.org/10.3390/fi17020057)
14. SoK: AI Agents for Blockchain, arXiv:2509.07131. DOI: [10.48550/arXiv.2509.07131](https://doi.org/10.48550/arXiv.2509.07131)
15. Y. Xie et al., "DeFort," ISSTA 2024. DOI: [10.1145/3650212.3652137](https://doi.org/10.1145/3650212.3652137)

---

## Author

**Sunil Gentyala** — Lead Cybersecurity and AI Security Consultant, HCL America Inc.
IEEE Senior Member · sunil.gentyala@ieee.org · [github.com/sunilgentyala](https://github.com/sunilgentyala)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
