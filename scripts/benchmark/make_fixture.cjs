// Generates a real Groth16 proof for build/input.json and writes the EVM-formatted
// fixture used by the Hardhat tests: test/fixtures/valid_proof.json
const snarkjs = require("snarkjs");
const fs = require("fs");
const h = (d) => "0x" + BigInt(d).toString(16);
(async () => {
  const input = JSON.parse(fs.readFileSync("build/input.json", "utf8"));
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input, "build/reasoning_anchor_js/reasoning_anchor.wasm", "build/reasoning_anchor_final.zkey");
  const vk = JSON.parse(fs.readFileSync("build/verification_key.json", "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!ok) throw new Error("honest proof failed to verify off-chain");
  fs.writeFileSync("build/proof.json", JSON.stringify(proof, null, 2));
  fs.writeFileSync("build/public.json", JSON.stringify(publicSignals, null, 2));
  const fixture = {
    proof: {
      A: { x: h(proof.pi_a[0]), y: h(proof.pi_a[1]) },
      B: { x: [h(proof.pi_b[0][1]), h(proof.pi_b[0][0])], y: [h(proof.pi_b[1][1]), h(proof.pi_b[1][0])] },
      C: { x: h(proof.pi_c[0]), y: h(proof.pi_c[1]) },
    },
    publicSignals: publicSignals.map(h),
    order: ["H_t", "tx_recipient", "tx_amount", "tx_slippage_bps", "tx_router_hash", "tx_token", "tx_deadline"],
  };
  fs.writeFileSync("test/fixtures/valid_proof.json", JSON.stringify(fixture, null, 2));
  console.log("fixture written; off-chain verify:", ok);
  process.exit(0);
})();
