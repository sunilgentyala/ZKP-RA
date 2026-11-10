// Prints the Solidity body of VerificationKey.load() from a snarkjs verification_key.json.
// Usage: node scripts/export_vk_solidity.cjs build/verification_key.json
const fs = require("fs");
const vk = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const h = (d) => "0x" + BigInt(d).toString(16);
const g1 = (p) => `Pairing.G1Point(\n            ${h(p[0])},\n            ${h(p[1])}\n        )`;
// snarkjs lists Fq2 as [real, imag]; the EVM pairing precompile expects [imag, real].
const g2 = (p) =>
  `Pairing.G2Point(\n            [\n                ${h(p[0][1])},\n                ${h(p[0][0])}\n            ],\n            [\n                ${h(p[1][1])},\n                ${h(p[1][0])}\n            ]\n        )`;
let out = `        vk.alpha = ${g1(vk.vk_alpha_1)};\n        vk.beta = ${g2(vk.vk_beta_2)};\n        vk.gamma = ${g2(vk.vk_gamma_2)};\n        vk.delta = ${g2(vk.vk_delta_2)};\n`;
vk.IC.forEach((p, i) => (out += `        vk.IC[${i}] = ${g1(p)};\n`));
console.log(out);
