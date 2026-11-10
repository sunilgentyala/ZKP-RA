// Proof-generation benchmark (witness + prove, snarkjs WASM). Run: node scripts/benchmark/bench.cjs
// TRIALS env var overrides the default of 100 trials.
const snarkjs = require("snarkjs");
const fs = require("fs");
const os = require("os");

const median = (a) => { const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]; };

async function main() {
  const wasmPath = "build/reasoning_anchor_js/reasoning_anchor.wasm";
  const zkeyPath = "build/reasoning_anchor_final.zkey";
  const input = JSON.parse(fs.readFileSync("build/input.json", "utf8"));
  const N = +process.env.TRIALS || 100;
  await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath); // warm-up, not counted
  const total = [];
  let proof, pub;
  for (let i = 0; i < N; i++) {
    const t0 = process.hrtime.bigint();
    const o = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
    total.push(Number(process.hrtime.bigint() - t0) / 1e6);
    proof = o.proof; pub = o.publicSignals;
  }
  const vk = JSON.parse(fs.readFileSync("build/verification_key.json", "utf8"));
  const ok = await snarkjs.groth16.verify(vk, pub, proof);
  const res = {
    date: new Date().toISOString().slice(0, 10), trials: N,
    cpu: `${os.cpus()[0].model} x ${os.cpus().length}`, node: process.version,
    median_ms: +median(total).toFixed(1), min_ms: +Math.min(...total).toFixed(1), max_ms: +Math.max(...total).toFixed(1),
    p95_ms: +pct(total, 0.95).toFixed(1), p99_ms: +pct(total, 0.99).toFixed(1), verifies: ok,
  };
  console.log(res);
  fs.writeFileSync("scripts/benchmark/results/bench_final_circuit.json", JSON.stringify(res, null, 2));
  fs.writeFileSync("build/proof.json", JSON.stringify(proof, null, 2));
  fs.writeFileSync("build/public.json", JSON.stringify(pub, null, 2));
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
