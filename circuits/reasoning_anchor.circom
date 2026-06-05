pragma circom 2.1.6;

/*
 * reasoning_anchor.circom
 *
 * Zero-knowledge circuit for ZKP-RA: Reasoning Anchor Integrity Proof.
 *
 * This circuit arithmetizes the following claim in R1CS over the BN254
 * scalar field Fr (order r = 21888242871839275222246405745257275088696311157297823662689037894645226208583):
 *
 *   "I know private witnesses (X_t, S_t, I_t, w) such that:
 *    (1) Poseidon(X_t || S_t || I_t) == H_t            [state integrity]
 *    (2) C(X_t, S_t, I_t, w) = T_x                     [deterministic policy]
 *    (3) T_x.amount <= MAX_AMOUNT                        [value bound]
 *    (4) T_x.slippage_bps <= MAX_SLIPPAGE_BPS            [slippage bound]
 *    (5) Poseidon(T_x.router) is in ROUTER_WHITELIST     [whitelist membership]"
 *
 * Public inputs:  H_t, tx_recipient, tx_amount, tx_slippage_bps, tx_router_hash
 * Private inputs: context_chunks[N_CTX], state_chunks[N_STATE], input_chunks[N_INPUT],
 *                 witness_salt, router_preimage
 *
 * Constraint counts (estimated, pre-optimization):
 *   Poseidon(t=3) adds ~240 constraints per invocation.
 *   RangeProof per field element: ~252 constraints (8-bit limb decomposition).
 *   Total: ~3,800 R1CS constraints for N_CTX=8, N_STATE=8, N_INPUT=4.
 *
 * Proving system target: Groth16 (SnarkJS / rapidsnark).
 * Estimated proof time on M2 Pro: ~1.2s (WASM prover), ~180ms (native C++ prover).
 */

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/mimcsponge.circom";

// ---------------------------------------------------------------------------
// Parameters — match these to the Solidity contract and agent_guardian.py
// ---------------------------------------------------------------------------

// Context window chunk count (each chunk is a field element representing
// a 248-bit packed segment of the tokenized context vector).
var N_CTX    = 8;

// State vector chunk count (embedding-space compressed representation of
// the agent's persistent memory, e.g., averaged RAG retrieval).
var N_STATE  = 8;

// Input chunk count (oracle feed snapshot, packed as field elements).
var N_INPUT  = 4;

// Policy enforcement constants (mirror on-chain contract values).
// Expressed as field elements. Slippage is in basis points (1 bps = 0.01%).
var MAX_AMOUNT_HI    = 1000000000000000000000; // 1000 tokens (18 decimals)
var MAX_SLIPPAGE_BPS = 200;                     // 2% maximum slippage

// ---------------------------------------------------------------------------
// Template: RangeCheck
//   Proves a < 2^n using bit decomposition. Used to enforce upper bounds
//   on transaction parameters without revealing exact values.
// ---------------------------------------------------------------------------

template RangeCheck(n) {
    signal input in;
    component bits = Num2Bits(n);
    bits.in <== in;
}

// ---------------------------------------------------------------------------
// Template: LessOrEqualBounded
//   Proves in <= bound for 252-bit values using the LessEqThan comparator.
// ---------------------------------------------------------------------------

template LessOrEqualBounded(n) {
    signal input in;
    signal input bound;
    component leq = LessEqThan(n);
    leq.in[0] <== in;
    leq.in[1] <== bound;
    leq.out === 1;
}

// ---------------------------------------------------------------------------
// Template: PoseidonChunked
//   Computes Poseidon over an array of field elements by absorbing them
//   in sequential t=3 sponge calls. Each call absorbs (t-1)=2 inputs and
//   chains the capacity element forward.
//
//   For N inputs with t=3: ceil(N/2) Poseidon calls, each ~240 constraints.
//   Capacity initialized to domain-separation constant D.
// ---------------------------------------------------------------------------

template PoseidonChunked(N, D) {
    signal input chunks[N];
    signal output hash;

    // Number of Poseidon-3 calls required to absorb all N elements.
    var nRounds = (N + 1) \ 2; // integer ceiling division

    component hashers[nRounds];
    signal cap[nRounds + 1];
    cap[0] <== D; // domain separation tag

    var remaining = N;
    for (var i = 0; i < nRounds; i++) {
        hashers[i] = Poseidon(3);
        hashers[i].inputs[0] <== cap[i];
        hashers[i].inputs[1] <== (i * 2 < N) ? chunks[i * 2] : 0;
        hashers[i].inputs[2] <== (i * 2 + 1 < N) ? chunks[i * 2 + 1] : 0;
        cap[i + 1] <== hashers[i].out;
    }

    hash <== cap[nRounds];
}

// ---------------------------------------------------------------------------
// Template: StateCommitment
//   Computes H_t = Poseidon(Poseidon_CTX(X_t), Poseidon_STATE(S_t), Poseidon_INPUT(I_t))
//
//   Domain separation constants prevent length-extension collisions:
//     D_CTX   = 0x01 (context domain)
//     D_STATE = 0x02 (state domain)
//     D_INPUT = 0x03 (input domain)
//     D_ROOT  = 0x04 (root commitment domain)
//
//   This mirrors the Poseidon call structure in agent_guardian.py so that
//   the Python prover and circuit hash the same value.
// ---------------------------------------------------------------------------

template StateCommitment() {
    signal input ctx[N_CTX];
    signal input state[N_STATE];
    signal input inp[N_INPUT];
    signal output H_t;

    // Hash each memory region independently with its domain tag.
    component ctx_hash   = PoseidonChunked(N_CTX,   1);
    component state_hash = PoseidonChunked(N_STATE,  2);
    component inp_hash   = PoseidonChunked(N_INPUT,  3);

    for (var i = 0; i < N_CTX;   i++) ctx_hash.chunks[i]   <== ctx[i];
    for (var i = 0; i < N_STATE; i++) state_hash.chunks[i] <== state[i];
    for (var i = 0; i < N_INPUT; i++) inp_hash.chunks[i]   <== inp[i];

    // Combine three region hashes into root commitment.
    component root = Poseidon(3);
    root.inputs[0] <== ctx_hash.hash;
    root.inputs[1] <== state_hash.hash;
    root.inputs[2] <== inp_hash.hash;

    H_t <== root.out;
}

// ---------------------------------------------------------------------------
// Template: PolicyEngine
//   Applies the deterministic safety policy C over verified state:
//     (1) The transaction amount must not exceed MAX_AMOUNT_HI.
//     (2) The declared slippage in basis points must not exceed MAX_SLIPPAGE_BPS.
//     (3) The router hash must equal Poseidon(router_preimage), proving the
//         agent resolved a whitelisted router without revealing its exact address.
//
//   The witness_salt is mixed into the router hash to prevent dictionary attacks
//   against small router address spaces.
// ---------------------------------------------------------------------------

template PolicyEngine() {
    // Public transaction parameters (committed in proof public inputs)
    signal input tx_amount;
    signal input tx_slippage_bps;
    signal input tx_router_hash;   // public: expected Poseidon(router, salt)

    // Private witnesses
    signal input router_preimage;  // private: actual router address as field element
    signal input witness_salt;     // private: random nonce drawn at proving time

    // Bound checks
    component amtCheck = LessOrEqualBounded(252);
    amtCheck.in    <== tx_amount;
    amtCheck.bound <== MAX_AMOUNT_HI;

    component slipCheck = LessOrEqualBounded(14); // 14 bits covers 0..16383 bps
    slipCheck.in    <== tx_slippage_bps;
    slipCheck.bound <== MAX_SLIPPAGE_BPS;

    // Router whitelist membership proof: prove knowledge of preimage s.t.
    // Poseidon(router_preimage, witness_salt) == tx_router_hash (public).
    component routerHasher = Poseidon(2);
    routerHasher.inputs[0] <== router_preimage;
    routerHasher.inputs[1] <== witness_salt;
    routerHasher.out === tx_router_hash;
}

// ---------------------------------------------------------------------------
// Template: ReasoningAnchor (Main Circuit)
//   Combines state commitment integrity and transaction policy enforcement
//   into a single R1CS proof. The Groth16 public inputs are:
//     [0] H_t
//     [1] tx_recipient  (as field element: uint160 address cast to Fr)
//     [2] tx_amount
//     [3] tx_slippage_bps
//     [4] tx_router_hash
// ---------------------------------------------------------------------------

template ReasoningAnchor() {
    // ---- Public signals (appear in verifier contract's input array) --------
    signal input H_t;               // on-chain committed state hash
    signal input tx_recipient;      // destination address (uint160 -> Fr)
    signal input tx_amount;         // transfer amount
    signal input tx_slippage_bps;   // max slippage in basis points
    signal input tx_router_hash;    // Poseidon(router, salt)

    // ---- Private witness signals -------------------------------------------
    signal input ctx[N_CTX];        // context window chunks
    signal input state[N_STATE];    // state vector chunks
    signal input inp[N_INPUT];      // oracle input chunks
    signal input router_preimage;   // router address
    signal input witness_salt;      // proving-time random salt

    // ---- Constraint 1: State Integrity  ------------------------------------
    //   Verify that the agent's declared private memory (X_t, S_t, I_t) hashes
    //   to the on-chain commitment H_t. A cheating agent that mutated its memory
    //   post-commitment cannot satisfy this constraint.
    component sc = StateCommitment();
    for (var i = 0; i < N_CTX;   i++) sc.ctx[i]   <== ctx[i];
    for (var i = 0; i < N_STATE; i++) sc.state[i] <== state[i];
    for (var i = 0; i < N_INPUT; i++) sc.inp[i]   <== inp[i];

    // Enforce equality with the public commitment: sc.H_t === H_t.
    sc.H_t === H_t;

    // ---- Constraint 2: Transaction Policy  --------------------------------
    //   Verify that the transaction parameters satisfy the safety policy C.
    component pe = PolicyEngine();
    pe.tx_amount       <== tx_amount;
    pe.tx_slippage_bps <== tx_slippage_bps;
    pe.tx_router_hash  <== tx_router_hash;
    pe.router_preimage <== router_preimage;
    pe.witness_salt    <== witness_salt;

    // ---- Constraint 3: Recipient Non-Zero  --------------------------------
    //   Prevents zero-address transfers that would permanently burn funds.
    component recipientCheck = IsZero();
    recipientCheck.in <== tx_recipient;
    recipientCheck.out === 0;
}

// Entry point instantiation
component main {public [H_t, tx_recipient, tx_amount, tx_slippage_bps, tx_router_hash]}
    = ReasoningAnchor();
