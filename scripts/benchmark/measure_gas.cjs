// Measures on-chain gas for ZKP-RA (commitState + verifyAndExecute) and the SimpleGuard baseline.
// Run: npx hardhat run scripts/benchmark/measure_gas.cjs
const hre = require("hardhat");
const fs = require("fs");
const fixture = JSON.parse(fs.readFileSync("test/fixtures/valid_proof.json", "utf8"));
const { ethers } = hre;

async function etchToken(addr, holder) {
  const F = await ethers.getContractFactory("MockERC20");
  const tmp = await F.deploy("TestToken", "TT");
  await tmp.waitForDeployment();
  await hre.network.provider.send("hardhat_setCode", [addr, await ethers.provider.getCode(await tmp.getAddress())]);
  const t = await ethers.getContractAt("MockERC20", addr);
  await t.mint(holder, ethers.parseEther("1000000"));
  return t;
}

async function main() {
  const [H, REC, AMT, SLIP, ROUTER, TOK, DL] = fixture.publicSignals;
  const tokenAddr = ethers.getAddress("0x" + BigInt(TOK).toString(16).padStart(40, "0"));
  const recipient = ethers.getAddress("0x" + BigInt(REC).toString(16).padStart(40, "0"));
  const routerHash = ethers.zeroPadValue(ROUTER, 32);
  const [, agent, guardian] = await ethers.getSigners();

  const V = await ethers.getContractFactory("ReasoningAnchorVerifier");
  const v = await V.deploy(ethers.parseEther("1000000"), 0);
  await v.waitForDeployment();
  const token = await etchToken(tokenAddr, await v.getAddress());
  await v.grantRole(await v.AGENT_ROLE(), agent.address);
  await v.grantRole(await v.GUARDIAN_ROLE(), guardian.address);
  await v.connect(guardian).setRouterWhitelist(routerHash, true);

  const c = await (await v.connect(agent).commitState(ethers.zeroPadValue(H, 32))).wait();
  const payload = { token: tokenAddr, recipient, amount: BigInt(AMT), maxSlippageBps: BigInt(SLIP), routerHash, deadline: BigInt(DL) };
  const r = await (await v.connect(agent).verifyAndExecute(fixture.proof, payload, 0n)).wait();

  const G = await ethers.getContractFactory("SimpleGuard");
  const g = await G.deploy(ethers.parseEther("1000000"));
  await g.waitForDeployment();
  await g.grantRole(await g.AGENT_ROLE(), agent.address);
  await g.setRouterWhitelist(routerHash, true);
  await token.mint(await g.getAddress(), ethers.parseEther("1000"));
  const b = await (await g.connect(agent).execute(tokenAddr, recipient, BigInt(AMT), 50, routerHash, BigInt(DL))).wait();

  console.log("=== ON-CHAIN GAS (local Hardhat network, final circuit) ===");
  console.log("ZKP-RA commitState gas:        ", c.gasUsed.toString());
  console.log("ZKP-RA verifyAndExecute gas:   ", r.gasUsed.toString());
  console.log("ZKP-RA total gas:              ", (c.gasUsed + r.gasUsed).toString());
  console.log("SimpleGuard execute gas:       ", b.gasUsed.toString());
  console.log("recipient balance:", (await token.balanceOf(recipient)).toString());
  const out = { date: new Date().toISOString().slice(0, 10), commitState: Number(c.gasUsed), verifyAndExecute: Number(r.gasUsed), total: Number(c.gasUsed + r.gasUsed), simpleGuard: Number(b.gasUsed) };
  fs.mkdirSync("scripts/benchmark/results", { recursive: true });
  fs.writeFileSync("scripts/benchmark/results/gas_final_circuit.json", JSON.stringify(out, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
