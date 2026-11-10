// ZKP-RA demo: five scenarios on a local Hardhat network.
// Run: npx hardhat run scripts/demo.cjs
// Needs build/ artifacts (npm run compile:circuit) and test/fixtures/valid_proof.json (node scripts/benchmark/make_fixture.cjs).
const hre = require("hardhat");
const snarkjs = require("snarkjs");
const fs = require("fs");
const { ethers } = hre;

const fixture = JSON.parse(fs.readFileSync("test/fixtures/valid_proof.json", "utf8"));
const input = JSON.parse(fs.readFileSync("build/input.json", "utf8"));
const WASM = "build/reasoning_anchor_js/reasoning_anchor.wasm";
const ZKEY = "build/reasoning_anchor_final.zkey";
const [H, REC, AMT, SLIP, ROUTER, TOK, DL] = fixture.publicSignals;
const tokenAddr = ethers.getAddress("0x" + BigInt(TOK).toString(16).padStart(40, "0"));
const recipient = ethers.getAddress("0x" + BigInt(REC).toString(16).padStart(40, "0"));
const routerHash = ethers.zeroPadValue(ROUTER, 32);
const stateHash = ethers.zeroPadValue(H, 32);
const cap = ethers.parseEther("1000000");

const line = (s) => console.log(s);
const head = (s) => console.log("\n=== " + s + " ===");
const payload = (o = {}) => ({ token: tokenAddr, recipient, amount: BigInt(AMT), maxSlippageBps: BigInt(SLIP), routerHash, deadline: BigInt(DL), ...o });
const clone = (o) => JSON.parse(JSON.stringify(o));

async function etchToken(holder) {
  const F = await ethers.getContractFactory("MockERC20");
  const tmp = await F.deploy("TestToken", "TT");
  await tmp.waitForDeployment();
  await hre.network.provider.send("hardhat_setCode", [tokenAddr, await ethers.provider.getCode(await tmp.getAddress())]);
  const t = await ethers.getContractAt("MockERC20", tokenAddr);
  await t.mint(holder, ethers.parseEther("1000000"));
  return t;
}

async function deploy(delay) {
  const [, agent, guardian] = await ethers.getSigners();
  const V = await ethers.getContractFactory("ReasoningAnchorVerifier");
  const v = await V.deploy(cap, delay);
  await v.waitForDeployment();
  const token = await etchToken(await v.getAddress());
  await v.grantRole(await v.AGENT_ROLE(), agent.address);
  await v.grantRole(await v.GUARDIAN_ROLE(), guardian.address);
  await v.connect(guardian).setRouterWhitelist(routerHash, true);
  return { v, token, agent, guardian };
}

async function expectRevert(promise) {
  try { await promise; return null; } catch (e) { return (e.shortMessage || e.message).split("\n")[0]; }
}
async function refusedToProve(inp) {
  try { await snarkjs.groth16.fullProve(inp, WASM, ZKEY); return false; } catch (e) { return true; }
}

async function main() {
  const { v, token, agent } = await deploy(0n);

  head("1. Honest payment");
  await v.connect(agent).commitState(stateHash);
  const before = await token.balanceOf(recipient);
  const r = await (await v.connect(agent).verifyAndExecute(fixture.proof, payload(), 0n)).wait();
  line(`proof verified on-chain, gas ${r.gasUsed}, tokens moved: ${ethers.formatEther((await token.balanceOf(recipient)) - before)}`);

  head("2. Memory tampering after the commitment");
  for (const [k, i] of [["ctx", 0], ["state", 3], ["inp", 2]]) {
    const bad = clone(input); bad[k][i] = "424242";
    line(`one ${k} chunk changed -> proof generation refused: ${await refusedToProve(bad)}`);
  }
  const G = await ethers.getContractFactory("SimpleGuard");
  const guard = await G.deploy(cap);
  await guard.waitForDeployment();
  await guard.grantRole(await guard.AGENT_ROLE(), agent.address);
  await guard.setRouterWhitelist(routerHash, true);
  await token.mint(await guard.getAddress(), ethers.parseEther("1000"));
  const attacker = ethers.getAddress("0x" + "ab".repeat(20));
  await guard.connect(agent).execute(tokenAddr, attacker, BigInt(AMT), 50, routerHash, BigInt(DL));
  line(`rule-only guard sends the same kind of payment to ${attacker.slice(0, 10)}...: ACCEPTED (balance ${ethers.formatEther(await token.balanceOf(attacker))})`);

  head("3. Substitution of a valid proof");
  const cases = [
    ["different token", payload({ token: ethers.getAddress("0x" + "11".repeat(20)) })],
    ["different deadline", payload({ deadline: BigInt(DL) + 1n })],
    ["different recipient", payload({ recipient: attacker })],
    ["different amount", payload({ amount: BigInt(AMT) - 1n })],
  ];
  for (const [name, pl] of cases) {
    const n = await v.agentNonce(agent.address);
    await v.connect(agent).commitState(stateHash);
    const err = await expectRevert(v.connect(agent).verifyAndExecute(fixture.proof, pl, n));
    line(`${name} -> ${err ? "REJECTED (" + err + ")" : "ACCEPTED (unexpected)"}`);
  }

  head("4. Timing");
  const t = await deploy(5n);
  await t.v.connect(t.agent).commitState(stateHash);
  let err = await expectRevert(t.v.connect(t.agent).verifyAndExecute(fixture.proof, payload(), 0n));
  line(`submitted in the next block -> ${err ? "REJECTED (" + err + ")" : "ACCEPTED (unexpected)"}`);
  await hre.network.provider.send("hardhat_mine", ["0x5"]);
  err = await expectRevert(t.v.connect(t.agent).verifyAndExecute(fixture.proof, payload(), 0n));
  line(`after 5 more blocks -> ${err ? "REJECTED (unexpected)" : "ACCEPTED"}`);

  head("5. Policy");
  const bigAmt = clone(input); bigAmt.tx_amount = "5000000000000000000000";
  line(`amount above the cap -> proof generation refused: ${await refusedToProve(bigAmt)}`);
  const bigSlip = clone(input); bigSlip.tx_slippage_bps = "500";
  line(`slippage above 2 percent -> proof generation refused: ${await refusedToProve(bigSlip)}`);
  const n = await v.agentNonce(agent.address);
  await v.connect(agent).commitState(stateHash);
  err = await expectRevert(v.connect(agent).verifyAndExecute(fixture.proof, payload({ routerHash: ethers.keccak256(ethers.toUtf8Bytes("other")) }), n));
  line(`router outside the whitelist -> ${err ? "REJECTED (" + err + ")" : "ACCEPTED (unexpected)"}`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
