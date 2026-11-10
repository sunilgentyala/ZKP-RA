// Chunk-scaling benchmark for the final circuit.
// Compiles variants with k times as many committed chunks (k = 1, 2, 4), runs a local Phase 2
// setup for each, and times fullProve over TRIALS runs. Needs circom on PATH or in ./bin.
// Usage: node scripts/benchmark/scale_bench.cjs <workdir>
// Writes scripts/benchmark/results/scale_final_circuit.json
const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");
const { buildPoseidon } = require("circomlibjs");

const N = +process.env.TRIALS || 100;
const work = path.resolve(process.argv[2] || "scale_work");
const repo = process.cwd();
const circom = path.join(repo, "bin", "circom.exe");
const sj = `node ${path.join(repo, "node_modules/snarkjs/build/cli.cjs")}`;
const med = (a) => { const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]; };

(async () => {
  fs.mkdirSync(work, { recursive: true });
  const P = await buildPoseidon(), F = P.F;
  const pc = (ch, D) => { let cap = BigInt(D); const n = ch.length, r = Math.floor((n + 1) / 2);
    for (let i = 0; i < r; i++) { const a = 2 * i < n ? ch[2 * i] : 0n, b = 2 * i + 1 < n ? ch[2 * i + 1] : 0n; cap = F.toObject(P([cap, a, b])); } return cap; };

  // Phase 1 for up to 2^15 constraints, generated locally (development only).
  const ptau = path.join(work, "pot15_final.ptau");
  if (!fs.existsSync(ptau)) {
    execSync(`${sj} powersoftau new bn128 15 ${work}/p0.ptau`, { stdio: "ignore" });
    execSync(`${sj} powersoftau contribute ${work}/p0.ptau ${work}/p1.ptau --name=dev -e="scale-bench-entropy-${Date.now()}"`, { stdio: "ignore" });
    execSync(`${sj} powersoftau prepare phase2 ${work}/p1.ptau ${ptau}`, { stdio: "ignore" });
  }
  const src = fs.readFileSync(path.join(repo, "circuits/reasoning_anchor.circom"), "utf8");
  const out = [];
  for (const k of [1, 2, 4]) {
    const dir = path.join(work, `k${k}`); fs.mkdirSync(dir, { recursive: true });
    const variant = src
      .replace("function nCtx() { return 8; }", `function nCtx() { return ${8 * k}; }`)
      .replace("function nState() { return 8; }", `function nState() { return ${8 * k}; }`)
      .replace("function nInput() { return 4; }", `function nInput() { return ${4 * k}; }`);
    fs.writeFileSync(path.join(dir, "ra.circom"), variant);
    execSync(`"${circom}" ${dir}/ra.circom --r1cs --wasm -l ${repo} -o ${dir}`, { stdio: "ignore" });
    const cons = +execSync(`${sj} r1cs info ${dir}/ra.r1cs`).toString().match(/Constraints: (\d+)/)[1];
    execSync(`${sj} groth16 setup ${dir}/ra.r1cs ${ptau} ${dir}/z0.zkey`, { stdio: "ignore" });
    execSync(`${sj} zkey contribute ${dir}/z0.zkey ${dir}/z1.zkey --name=bench -e="bench-${k}-${Date.now()}"`, { stdio: "ignore" });
    execSync(`${sj} zkey export verificationkey ${dir}/z1.zkey ${dir}/vk.json`, { stdio: "ignore" });

    const nc = 8 * k, ns = 8 * k, ni = 4 * k;
    const ctx = [...Array(nc)].map((_, i) => BigInt(i + 1)), st = [...Array(ns)].map((_, i) => BigInt(i + 11)), inp = [...Array(ni)].map((_, i) => BigInt(i + 21));
    const salt = 424242424242424242424242n;
    const H = F.toObject(P([pc(ctx, 1), pc(st, 2), pc(inp, 3), salt]));
    const rh = F.toObject(P([12345n, 67890n]));
    const input = { H_t: H.toString(), tx_recipient: "999", tx_amount: "500000000000000000000", tx_slippage_bps: "50", tx_router_hash: rh.toString(),
      tx_token: BigInt("0x" + "7a".repeat(20)).toString(), tx_deadline: "4102444800",
      ctx: ctx.map(String), state: st.map(String), inp: inp.map(String), router_preimage: "12345", witness_salt: "67890", commit_salt: salt.toString() };
    const wasm = `${dir}/ra_js/ra.wasm`, zkey = `${dir}/z1.zkey`;
    await snarkjs.groth16.fullProve(input, wasm, zkey); // warm-up
    const tot = []; let pr, pub;
    for (let i = 0; i < N; i++) { const t0 = process.hrtime.bigint(); const o = await snarkjs.groth16.fullProve(input, wasm, zkey); tot.push(Number(process.hrtime.bigint() - t0) / 1e6); pr = o.proof; pub = o.publicSignals; }
    const ok = await snarkjs.groth16.verify(JSON.parse(fs.readFileSync(`${dir}/vk.json`)), pub, pr);
    const res = { k, chunks: nc + ns + ni, constraints: cons, trials: N, median_ms: +med(tot).toFixed(1), min_ms: +Math.min(...tot).toFixed(1), max_ms: +Math.max(...tot).toFixed(1), p95_ms: +pct(tot, 0.95).toFixed(1), p99_ms: +pct(tot, 0.99).toFixed(1), verifies: ok };
    console.log(JSON.stringify(res)); out.push(res);
  }
  const meta = { date: new Date().toISOString().slice(0, 10), cpu: `${os.cpus()[0].model} x ${os.cpus().length}`, node: process.version, results: out };
  fs.writeFileSync(path.join(repo, "scripts/benchmark/results/scale_final_circuit.json"), JSON.stringify(meta, null, 2));
  console.log("DONE");
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
