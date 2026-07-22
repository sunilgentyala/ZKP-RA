const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");

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

  // deterministic-but-arbitrary test context/state/input chunks
  const ctx = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
  const state = [11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n];
  const inp = [21n, 22n, 23n, 24n];

  const ctxHash = poseidonChunked(ctx, 1);
  const stateHash = poseidonChunked(state, 2);
  const inpHash = poseidonChunked(inp, 3);
  const H_t = F.toObject(poseidon([ctxHash, stateHash, inpHash]));

  const router_preimage = 12345n;
  const witness_salt = 67890n;
  const tx_router_hash = F.toObject(poseidon([router_preimage, witness_salt]));

  const input = {
    H_t: H_t.toString(),
    tx_recipient: "999",
    tx_amount: "500000000000000000000", // 500 tokens, under 1000 cap
    tx_slippage_bps: "50",
    tx_router_hash: tx_router_hash.toString(),
    ctx: ctx.map(String),
    state: state.map(String),
    inp: inp.map(String),
    router_preimage: router_preimage.toString(),
    witness_salt: witness_salt.toString(),
  };

  fs.writeFileSync("build/input.json", JSON.stringify(input, null, 2));
  console.log("wrote build/input.json");
  console.log(input);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
