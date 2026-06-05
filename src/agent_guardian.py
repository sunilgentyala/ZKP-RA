"""
agent_guardian.py — ZKP-RA Agent Guardian Daemon

Asynchronous Python daemon that wraps an LLM-powered DeFi execution agent and
enforces state-commitment integrity before every on-chain transaction.

Architecture:
  1. Intercepts every tool call originating from the LLM agent.
  2. Snapshots and chunks the active context window, state vector, and oracle inputs.
  3. Computes H_t = Poseidon(X_t, S_t, I_t) using the field-native Python implementation.
  4. Submits H_t to the on-chain ReasoningAnchorVerifier via commitState().
  5. Calls the SnarkJS/rapidsnark prover backend to generate proof pi.
  6. Submits (pi, TxPayload) to verifyAndExecute() on the verifier contract.
  7. Blocks any transaction that fails any of these steps.

Dependencies:
    pip install web3 aiohttp poseidon-hash eth-abi pydantic structlog langchain-core
    npm install -g snarkjs  (or provide path to rapidsnark binary)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

import aiohttp
import structlog
from eth_abi import encode as abi_encode
from pydantic import BaseModel, field_validator
from web3 import AsyncWeb3
from web3.middleware import ExtraDataToPOAMiddleware

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants — must mirror circuit parameters in reasoning_anchor.circom
# ---------------------------------------------------------------------------

FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583

N_CTX   = 8    # context window chunk count
N_STATE = 8    # state vector chunk count
N_INPUT = 4    # oracle input chunk count

# Domain separation tags for PoseidonChunked (must match circuit)
DOMAIN_CTX   = 1
DOMAIN_STATE = 2
DOMAIN_INPUT = 3
DOMAIN_ROOT  = 4

# Policy constants (must match circuit and Verifier.sol)
MAX_AMOUNT_WEI    = 1_000_000_000_000_000_000_000   # 1000 tokens (18 decimals)
MAX_SLIPPAGE_BPS  = 200                              # 2% maximum slippage

# ---------------------------------------------------------------------------
# Poseidon hash wrapper
#   Uses the poseidon-hash PyPI package which implements the same BN254-native
#   Poseidon permutation as circomlib's Poseidon template.
# ---------------------------------------------------------------------------

try:
    from poseidon_hash.poseidon import Poseidon
    _poseidon_t3 = Poseidon(p=FIELD_MODULUS, security_level=128, alpha=5,
                             input_rate=2, t=3)

    def poseidon3(a: int, b: int, c: int) -> int:
        return _poseidon_t3.run_hash([a, b, c])

    def poseidon2(a: int, b: int) -> int:
        return _poseidon_t3.run_hash([a, b])

except ImportError:
    # Fallback: naive reference using MiMC-style compression (NOT production-safe).
    # Replace with proper Poseidon bindings before deployment.
    log.warning("poseidon_hash not installed; using insecure SHA-256 stub")

    def poseidon3(a: int, b: int, c: int) -> int:
        raw = hashlib.sha256(
            (a).to_bytes(32, "big") +
            (b).to_bytes(32, "big") +
            (c).to_bytes(32, "big")
        ).digest()
        return int.from_bytes(raw, "big") % FIELD_MODULUS

    def poseidon2(a: int, b: int) -> int:
        raw = hashlib.sha256(
            (a).to_bytes(32, "big") +
            (b).to_bytes(32, "big")
        ).digest()
        return int.from_bytes(raw, "big") % FIELD_MODULUS

# ---------------------------------------------------------------------------
# Field element utilities
# ---------------------------------------------------------------------------

def to_field(x: int) -> int:
    return x % FIELD_MODULUS

def pack_bytes_to_field_elements(data: bytes, n: int) -> list[int]:
    """
    Pack `data` into exactly `n` field elements by splitting into 31-byte
    chunks (< 248-bit, safely inside BN254 Fr) and zero-padding the last chunk.
    """
    chunk_size = 31
    elements: list[int] = []
    for i in range(n):
        start = i * chunk_size
        chunk = data[start:start + chunk_size]
        if not chunk:
            elements.append(0)
        else:
            padded = chunk.ljust(chunk_size, b"\x00")
            elements.append(int.from_bytes(padded, "big") % FIELD_MODULUS)
    return elements

def poseidon_chunked(chunks: list[int], domain: int) -> int:
    """
    Sponge absorption of `chunks` using t=3 Poseidon with domain separation.
    Mirrors the PoseidonChunked template in reasoning_anchor.circom.
    """
    cap = domain
    n = len(chunks)
    n_rounds = (n + 1) // 2
    for i in range(n_rounds):
        c0 = cap
        c1 = chunks[i * 2]     if i * 2 < n     else 0
        c2 = chunks[i * 2 + 1] if i * 2 + 1 < n else 0
        cap = poseidon3(c0, c1, c2)
    return cap

def compute_state_hash(
    ctx_chunks:   list[int],
    state_chunks: list[int],
    input_chunks: list[int],
) -> int:
    """
    Compute H_t = Poseidon(Poseidon_CTX(X_t), Poseidon_STATE(S_t), Poseidon_INPUT(I_t)).
    Must produce identical output to the StateCommitment circuit template.
    """
    h_ctx   = poseidon_chunked(ctx_chunks,   DOMAIN_CTX)
    h_state = poseidon_chunked(state_chunks, DOMAIN_STATE)
    h_input = poseidon_chunked(input_chunks, DOMAIN_INPUT)
    return poseidon3(h_ctx, h_state, h_input)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentState:
    context_raw:   bytes           # serialized context window (UTF-8 encoded token IDs)
    state_raw:     bytes           # serialized state vector (float32 embeddings, big-endian)
    oracle_inputs: list[dict]      # structured oracle feed snapshot
    timestamp:     float = field(default_factory=time.time)


class TxPayload(BaseModel):
    token:           str            # ERC-20 contract address (checksummed)
    recipient:       str            # destination address
    amount:          int            # transfer amount in base units (wei)
    max_slippage_bps: int           # max slippage in basis points
    router:          str            # whitelisted router address
    deadline:        int            # Unix timestamp

    @field_validator("amount")
    @classmethod
    def amount_in_bounds(cls, v: int) -> int:
        if not (0 < v <= MAX_AMOUNT_WEI):
            raise ValueError(f"amount {v} outside [1, {MAX_AMOUNT_WEI}]")
        return v

    @field_validator("max_slippage_bps")
    @classmethod
    def slippage_in_bounds(cls, v: int) -> int:
        if not (0 <= v <= MAX_SLIPPAGE_BPS):
            raise ValueError(f"slippage_bps {v} exceeds MAX_SLIPPAGE_BPS={MAX_SLIPPAGE_BPS}")
        return v


@dataclass
class ProofBundle:
    proof: dict        # Groth16 proof: {A: [x,y], B: [[x0,x1],[y0,y1]], C: [x,y]}
    public_inputs: list[str]   # hex strings matching circuit public signal order
    nullifier: bytes   # keccak256(proof.A.x, proof.A.y, agent_address, nonce)


# ---------------------------------------------------------------------------
# Prover backend: wraps SnarkJS CLI / rapidsnark binary
# ---------------------------------------------------------------------------

class ProverBackend:
    """
    Calls the SnarkJS WASM prover or the native rapidsnark binary to generate
    a Groth16 proof for reasoning_anchor.circom.

    Directory layout expected:
        circuits/
            reasoning_anchor.wasm       (compiled circuit)
            reasoning_anchor_final.zkey  (Groth16 proving key, post-ceremony)
    """

    def __init__(
        self,
        wasm_path: Path,
        zkey_path: Path,
        snarkjs_bin: str = "snarkjs",
        rapidsnark_bin: Optional[str] = None,
    ):
        self.wasm_path      = wasm_path
        self.zkey_path      = zkey_path
        self.snarkjs_bin    = snarkjs_bin
        self.rapidsnark_bin = rapidsnark_bin

    async def generate_proof(
        self,
        ctx_chunks:    list[int],
        state_chunks:  list[int],
        input_chunks:  list[int],
        tx_payload:    TxPayload,
        witness_salt:  int,
    ) -> ProofBundle:
        """
        Build the witness JSON, invoke the prover, and return a ProofBundle.
        Runs the CPU-bound prover call in a thread pool to not block the event loop.
        """
        router_addr_int = int(tx_payload.router, 16)
        router_hash     = poseidon2(router_addr_int, witness_salt)
        H_t             = compute_state_hash(ctx_chunks, state_chunks, input_chunks)
        recipient_int   = int(tx_payload.recipient, 16)

        input_json = {
            # Public signals
            "H_t":              str(H_t),
            "tx_recipient":     str(recipient_int),
            "tx_amount":        str(tx_payload.amount),
            "tx_slippage_bps":  str(tx_payload.max_slippage_bps),
            "tx_router_hash":   str(router_hash),
            # Private witnesses
            "ctx":              [str(x) for x in ctx_chunks],
            "state":            [str(x) for x in state_chunks],
            "inp":              [str(x) for x in input_chunks],
            "router_preimage":  str(router_addr_int),
            "witness_salt":     str(witness_salt),
        }

        return await asyncio.get_event_loop().run_in_executor(
            None, self._run_prover_sync, input_json, H_t,
            tx_payload.amount, tx_payload.max_slippage_bps, router_hash, recipient_int
        )

    def _run_prover_sync(
        self,
        input_json: dict,
        H_t: int,
        tx_amount: int,
        tx_slippage_bps: int,
        tx_router_hash: int,
        tx_recipient: int,
    ) -> ProofBundle:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            input_file  = tmp / "input.json"
            wtns_file   = tmp / "witness.wtns"
            proof_file  = tmp / "proof.json"
            public_file = tmp / "public.json"

            input_file.write_text(json.dumps(input_json))

            # Step 1: Generate witness
            subprocess.run(
                [
                    "node", self.snarkjs_bin, "wtns", "calculate",
                    str(self.wasm_path), str(input_file), str(wtns_file),
                ],
                check=True, capture_output=True, text=True
            )

            # Step 2: Generate proof (prefer rapidsnark for ~10x speedup)
            if self.rapidsnark_bin and Path(self.rapidsnark_bin).exists():
                subprocess.run(
                    [
                        self.rapidsnark_bin,
                        str(self.zkey_path), str(wtns_file),
                        str(proof_file), str(public_file),
                    ],
                    check=True, capture_output=True, text=True
                )
            else:
                subprocess.run(
                    [
                        "node", self.snarkjs_bin, "groth16", "prove",
                        str(self.zkey_path), str(wtns_file),
                        str(proof_file), str(public_file),
                    ],
                    check=True, capture_output=True, text=True
                )

            proof  = json.loads(proof_file.read_text())
            public = json.loads(public_file.read_text())

            # Build nullifier: keccak256(A.x || A.y)  —  full derivation in contract
            nullifier = self._derive_nullifier(proof)

            return ProofBundle(
                proof=proof,
                public_inputs=public,
                nullifier=nullifier,
            )

    @staticmethod
    def _derive_nullifier(proof: dict) -> bytes:
        ax = int(proof["pi_a"][0])
        ay = int(proof["pi_a"][1])
        raw = abi_encode(["uint256", "uint256"], [ax, ay])
        from web3 import Web3
        return Web3.keccak(raw)


# ---------------------------------------------------------------------------
# On-chain interface: wraps the ReasoningAnchorVerifier contract
# ---------------------------------------------------------------------------

class VerifierContractClient:
    def __init__(
        self,
        w3: AsyncWeb3,
        contract_address: str,
        abi_path: Path,
        agent_private_key: str,
    ):
        abi = json.loads(abi_path.read_text())
        self.contract     = w3.eth.contract(
            address=AsyncWeb3.to_checksum_address(contract_address),
            abi=abi,
        )
        self.w3           = w3
        self.account      = w3.eth.account.from_key(agent_private_key)
        self.agent_address = self.account.address

    async def commit_state(self, state_hash: int) -> tuple[str, int]:
        """
        Submit commitState(H_t) transaction. Returns (tx_hash, nonce_used).
        """
        nonce = await self.contract.functions.agentNonce(self.agent_address).call()
        h_bytes = state_hash.to_bytes(32, "big")

        tx = await self.contract.functions.commitState(h_bytes).build_transaction({
            "from":   self.agent_address,
            "nonce":  await self.w3.eth.get_transaction_count(self.agent_address),
            "gas":    80_000,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = await self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        if receipt["status"] != 1:
            raise RuntimeError(f"commitState reverted: {tx_hash.hex()}")

        log.info("state_committed", tx=tx_hash.hex(), nonce=nonce, hash=hex(state_hash))
        return tx_hash.hex(), nonce

    async def verify_and_execute(
        self,
        proof_bundle: ProofBundle,
        tx_payload:   TxPayload,
        commit_nonce: int,
    ) -> str:
        """
        Submit verifyAndExecute() with the Groth16 proof and transaction payload.
        Returns the settlement transaction hash.
        """
        proof = proof_bundle.proof
        pf = {
            "A": {
                "x": int(proof["pi_a"][0]),
                "y": int(proof["pi_a"][1]),
            },
            "B": {
                "x": [int(proof["pi_b"][0][1]), int(proof["pi_b"][0][0])],
                "y": [int(proof["pi_b"][1][1]), int(proof["pi_b"][1][0])],
            },
            "C": {
                "x": int(proof["pi_c"][0]),
                "y": int(proof["pi_c"][1]),
            },
        }

        from web3 import Web3
        router_hash = Web3.keccak(
            AsyncWeb3.to_bytes(hexstr=tx_payload.router)
        )

        payload = (
            AsyncWeb3.to_checksum_address(tx_payload.token),
            AsyncWeb3.to_checksum_address(tx_payload.recipient),
            tx_payload.amount,
            tx_payload.max_slippage_bps,
            router_hash,
            tx_payload.deadline,
        )

        tx = await self.contract.functions.verifyAndExecute(
            pf, payload, commit_nonce, proof_bundle.nullifier
        ).build_transaction({
            "from":  self.agent_address,
            "nonce": await self.w3.eth.get_transaction_count(self.agent_address),
            "gas":   500_000,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = await self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt["status"] != 1:
            raise RuntimeError(f"verifyAndExecute reverted: {tx_hash.hex()}")

        log.info("transfer_executed",
                 tx=tx_hash.hex(),
                 token=tx_payload.token,
                 recipient=tx_payload.recipient,
                 amount=tx_payload.amount)
        return tx_hash.hex()


# ---------------------------------------------------------------------------
# Agent Guardian: main interceptor daemon
# ---------------------------------------------------------------------------

class AgentGuardian:
    """
    Wraps a LangChain-compatible agent (or any callable that accepts a tool call
    dict and returns a tool result). Intercepts every tool call of type
    'execute_defi_transaction', enforces the ZKP-RA proof pipeline, and only
    forwards the call to the network after successful proof verification.

    All other tool calls (e.g., read-only oracle queries) are passed through
    transparently after logging.
    """

    GUARDED_TOOL = "execute_defi_transaction"

    def __init__(
        self,
        prover:   ProverBackend,
        verifier: VerifierContractClient,
    ):
        self.prover   = prover
        self.verifier = verifier

    async def intercept(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        agent_state: AgentState,
    ) -> dict[str, Any]:
        """
        Central interception point. Returns the tool execution result or raises
        RuntimeError if the proof pipeline fails.
        """
        if tool_name != self.GUARDED_TOOL:
            log.debug("tool_passthrough", tool=tool_name)
            return {"status": "passthrough", "tool": tool_name}

        log.info("intercepting_defi_tx", args=tool_args)

        # ---- Step 1: Parse and validate the transaction payload --------------
        tx = TxPayload(**tool_args)

        # ---- Step 2: Chunk agent state into field elements -------------------
        ctx_chunks   = pack_bytes_to_field_elements(agent_state.context_raw, N_CTX)
        state_chunks = pack_bytes_to_field_elements(agent_state.state_raw,   N_STATE)
        input_raw    = json.dumps(agent_state.oracle_inputs).encode()
        input_chunks = pack_bytes_to_field_elements(input_raw,               N_INPUT)

        # ---- Step 3: Compute H_t --------------------------------------------
        H_t = compute_state_hash(ctx_chunks, state_chunks, input_chunks)
        log.info("state_hash_computed", H_t=hex(H_t))

        # ---- Step 4: Commit H_t on-chain ------------------------------------
        _, commit_nonce = await self.verifier.commit_state(H_t)

        # ---- Step 5: Generate zk-SNARK proof --------------------------------
        witness_salt = secrets.randbits(248) % FIELD_MODULUS
        proof_bundle = await self.prover.generate_proof(
            ctx_chunks, state_chunks, input_chunks,
            tx, witness_salt
        )
        log.info("proof_generated", nullifier=proof_bundle.nullifier.hex())

        # ---- Step 6: Submit proof + payload to verifier contract ------------
        settlement_tx = await self.verifier.verify_and_execute(
            proof_bundle, tx, commit_nonce
        )

        return {
            "status":         "verified_and_executed",
            "settlement_tx":  settlement_tx,
            "nullifier":      proof_bundle.nullifier.hex(),
            "state_hash":     hex(H_t),
        }


# ---------------------------------------------------------------------------
# Guardian daemon entrypoint
# ---------------------------------------------------------------------------

async def run_guardian_daemon(config: dict[str, Any]) -> None:
    rpc_url          = config["rpc_url"]
    contract_address = config["contract_address"]
    abi_path         = Path(config["abi_path"])
    agent_key        = os.environ["AGENT_PRIVATE_KEY"]
    wasm_path        = Path(config["wasm_path"])
    zkey_path        = Path(config["zkey_path"])
    rapidsnark_bin   = config.get("rapidsnark_bin")

    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    prover = ProverBackend(
        wasm_path=wasm_path,
        zkey_path=zkey_path,
        rapidsnark_bin=rapidsnark_bin,
    )
    verifier_client = VerifierContractClient(
        w3=w3,
        contract_address=contract_address,
        abi_path=abi_path,
        agent_private_key=agent_key,
    )
    guardian = AgentGuardian(prover=prover, verifier=verifier_client)

    log.info("guardian_daemon_started",
             contract=contract_address,
             rpc=rpc_url)

    # The daemon exposes a local UNIX socket or HTTP endpoint that the LLM
    # agent framework routes tool calls through. For production, replace
    # this stub loop with the appropriate MCP server or LangChain callback.
    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    import sys
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    cfg = json.loads(Path(cfg_path).read_text())
    asyncio.run(run_guardian_daemon(cfg))
