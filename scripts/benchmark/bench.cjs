const snarkjs = require("snarkjs");
const fs = require("fs");
const os = require("os");

async function main() {
  const wasmPath = "build/reasoning_anchor_js/reasoning_anchor.wasm";
  const zkeyPath = "build/reasoning_anchor_final.zkey";
  const input = JSON.parse(fs.readFileSync("build/input.json", "utf8"));

  const N = 20;
  const witnessMs = [];
  const proveMs = [];
  const totalMs = [];
  let lastProof, lastPublic;

  for (let i = 0; i < N; i++) {
    const t0 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath
    );
    const t1 = process.hrtime.bigint();
    totalMs.push(Number(t1 - t0) / 1e6);
    lastProof = proof;
    lastPublic = publicSignals;
  }

  function median(arr) {
    const s = [...arr].sort((a, b) => a - b);
    const mid = Math.floor(s.length / 2);
    return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
  }

  console.log("CPU:", os.cpus()[0].model, "x", os.cpus().length);
  console.log("Node:", process.version);
  console.log(`fullProve (witness+prove combined), N=${N} trials`);
  console.log("median total (ms):", median(totalMs).toFixed(2));
  console.log("min (ms):", Math.min(...totalMs).toFixed(2));
  console.log("max (ms):", Math.max(...totalMs).toFixed(2));
  console.log("all (ms):", totalMs.map((x) => x.toFixed(1)).join(", "));

  const vkey = JSON.parse(fs.readFileSync("build/verification_key.json", "utf8"));
  const ok = await snarkjs.groth16.verify(vkey, lastPublic, lastProof);
  console.log("proof verifies (off-chain, snarkjs):", ok);

  fs.writeFileSync("build/proof.json", JSON.stringify(lastProof, null, 2));
  fs.writeFileSync("build/public.json", JSON.stringify(lastPublic, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
