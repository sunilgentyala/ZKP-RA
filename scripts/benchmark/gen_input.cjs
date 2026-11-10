// Builds build/input.json for the ZKP-RA circuit (salted commitment, token and deadline bound).
// Usage: node scripts/benchmark/gen_input.cjs
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");

const TEST_TOKEN = BigInt("0x" + "7a".repeat(20)); // fixed test token address
const TEST_DEADLINE = 4102444800n;                 // 2100-01-01 UTC, fixed so proofs are reusable in tests

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  function poseidonChunked(chunks, D) {
    let cap = BigInt(D);
    const n = chunks.length;
    const nRounds = Math.floor((n + 1) / 2);
    for (let i = 0; i < nRounds; i++) {
      const a = i * 2 < n ? chunks[i * 2] : 0n;
      const b = i * 2 + 1 < n ? chunks[i * 2 + 1] : 0n;
      cap = F.toObject(poseidon([cap, a, b]));
    }
    return cap;
  }

  const ctx = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
  const state = [11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n];
  const inp = [21n, 22n, 23n, 24n];
  const commit_salt = 424242424242424242424242n; // fixed for reproducibility; use a fresh random value in practice

  const ctxHash = poseidonChunked(ctx, 1);
  const stateHash = poseidonChunked(state, 2);
  const inpHash = poseidonChunked(inp, 3);
  const H_t = F.toObject(poseidon([ctxHash, stateHash, inpHash, commit_salt]));

  const router_preimage = 12345n;
  const witness_salt = 67890n;
  const tx_router_hash = F.toObject(poseidon([router_preimage, witness_salt]));

  const input = {
    H_t: H_t.toString(),
    tx_recipient: "999",
    tx_amount: "500000000000000000000",
    tx_slippage_bps: "50",
    tx_router_hash: tx_router_hash.toString(),
    tx_token: TEST_TOKEN.toString(),
    tx_deadline: TEST_DEADLINE.toString(),
    ctx: ctx.map(String),
    state: state.map(String),
    inp: inp.map(String),
    router_preimage: router_preimage.toString(),
    witness_salt: witness_salt.toString(),
    commit_salt: commit_salt.toString(),
  };
  fs.writeFileSync("build/input.json", JSON.stringify(input, null, 2));
  console.log("wrote build/input.json");
}
main().catch((e) => { console.error(e); process.exit(1); });
