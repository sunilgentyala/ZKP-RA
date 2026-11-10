// Attack simulations against the final circuit and setup. Run: node scripts/benchmark/tamper_test.cjs
const snarkjs = require("snarkjs");
const fs = require("fs");
const WASM = "build/reasoning_anchor_js/reasoning_anchor.wasm";
const ZKEY = "build/reasoning_anchor_final.zkey";
const clone = (o) => JSON.parse(JSON.stringify(o));
const NAMES = ["H_t", "tx_recipient", "tx_amount", "tx_slippage_bps", "tx_router_hash", "tx_token", "tx_deadline"];

async function refused(input) {
  try { await snarkjs.groth16.fullProve(input, WASM, ZKEY); return false; } catch (e) { return true; }
}

(async () => {
  const vk = JSON.parse(fs.readFileSync("build/verification_key.json"));
  const input = JSON.parse(fs.readFileSync("build/input.json"));
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  console.log("honest proof verifies:", await snarkjs.groth16.verify(vk, publicSignals, proof));
  console.log("public signals:", publicSignals.length);

  for (let i = 0; i < publicSignals.length; i++) {
    const ps = [...publicSignals];
    ps[i] = (BigInt(ps[i]) + 1n).toString();
    console.log(`tampered public input ${i} (${NAMES[i]}) verifies:`, await snarkjs.groth16.verify(vk, ps, proof));
  }
  const p2 = clone(proof);
  p2.pi_a[0] = (BigInt(p2.pi_a[0]) + 1n).toString();
  let r;
  try { r = await snarkjs.groth16.verify(vk, publicSignals, p2); } catch (e) { r = "error/rejected"; }
  console.log("tampered proof point A verifies:", r);

  // Post-commitment memory mutation: the committed H_t stays fixed, the witness changes.
  for (const [k, v] of [["ctx", 0], ["state", 3], ["inp", 2]]) {
    const b = clone(input); b[k][v] = "424242";
    console.log(`poisoned ${k} chunk -> proof generation refused:`, await refused(b));
  }
  const bs = clone(input); bs.commit_salt = "1";
  console.log("wrong commitment salt -> proof generation refused:", await refused(bs));

  const b2 = clone(input); b2.tx_amount = "5000000000000000000000";
  console.log("amount above policy cap -> proof generation refused:", await refused(b2));
  const b3 = clone(input); b3.tx_slippage_bps = "500";
  console.log("slippage above policy cap -> proof generation refused:", await refused(b3));
  const b4 = clone(input); b4.router_preimage = "999999";
  console.log("non-whitelisted router preimage -> proof generation refused:", await refused(b4));
  const b5 = clone(input); b5.tx_recipient = "0";
  console.log("zero recipient -> proof generation refused:", await refused(b5));
  const b6 = clone(input); b6.tx_token = (2n ** 160n).toString();
  console.log("token outside 160 bits -> proof generation refused:", await refused(b6));
  const b7 = clone(input); b7.tx_deadline = (2n ** 64n).toString();
  console.log("deadline outside 64 bits -> proof generation refused:", await refused(b7));
  process.exit(0);
})();
