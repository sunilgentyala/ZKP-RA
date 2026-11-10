/**
 * Verifier.test.js: integration tests for ReasoningAnchorVerifier and the
 * SimpleGuard baseline.
 *
 * test/fixtures/valid_proof.json holds a real Groth16 proof produced by
 * scripts/benchmark/make_fixture.cjs against circuits/reasoning_anchor.circom
 * and the dev trusted setup whose key is hardcoded in contracts/Verifier.sol.
 * Regenerate the fixture whenever the circuit or the setup changes.
 *
 * Public signal order: [H_t, recipient, amount, slippageBps, routerHash, token, deadline].
 */
const { expect } = require("chai");
const hre = require("hardhat");
const { ethers } = hre;
const fixture = require("./fixtures/valid_proof.json");

const VALID_PROOF = fixture.proof;
const [S_H, S_RECIPIENT, S_AMOUNT, S_SLIP, S_ROUTER, S_TOKEN, S_DEADLINE] = fixture.publicSignals;

const TEST_STATE_HASH = ethers.zeroPadValue(S_H, 32);
const TEST_ROUTER_HASH = ethers.zeroPadValue(S_ROUTER, 32);
const TEST_RECIPIENT = ethers.getAddress("0x" + BigInt(S_RECIPIENT).toString(16).padStart(40, "0"));
const TEST_TOKEN = ethers.getAddress("0x" + BigInt(S_TOKEN).toString(16).padStart(40, "0"));
const TEST_AMOUNT = BigInt(S_AMOUNT);
const TEST_SLIPPAGE_BPS = BigInt(S_SLIP);
const TEST_DEADLINE = BigInt(S_DEADLINE);

const MAX_TRANSFER_CAP = ethers.parseEther("1000000");
const FIELD_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function deployToken(holder) {
  // The proof binds the token address, so the mock token must live at the
  // address the proof was generated for. Etch the runtime code there.
  const Factory = await ethers.getContractFactory("MockERC20");
  const tmp = await Factory.deploy("TestToken", "TT");
  await tmp.waitForDeployment();
  const code = await ethers.provider.getCode(await tmp.getAddress());
  await hre.network.provider.send("hardhat_setCode", [TEST_TOKEN, code]);
  const token = await ethers.getContractAt("MockERC20", TEST_TOKEN);
  await token.mint(holder, ethers.parseEther("10000000"));
  return token;
}

function payload(overrides = {}) {
  return {
    token: TEST_TOKEN,
    recipient: TEST_RECIPIENT,
    amount: TEST_AMOUNT,
    maxSlippageBps: TEST_SLIPPAGE_BPS,
    routerHash: TEST_ROUTER_HASH,
    deadline: TEST_DEADLINE,
    ...overrides,
  };
}

describe("ReasoningAnchorVerifier", function () {
  let verifier, token, owner, agent, outsider, guardian;

  async function setup(delay) {
    [owner, agent, outsider, guardian] = await ethers.getSigners();
    const V = await ethers.getContractFactory("ReasoningAnchorVerifier");
    verifier = await V.deploy(MAX_TRANSFER_CAP, delay);
    await verifier.waitForDeployment();
    token = await deployToken(await verifier.getAddress());
    await verifier.grantRole(await verifier.AGENT_ROLE(), agent.address);
    await verifier.grantRole(await verifier.GUARDIAN_ROLE(), guardian.address);
    await verifier.connect(guardian).setRouterWhitelist(TEST_ROUTER_HASH, true);
  }

  const nextNonce = () => verifier.agentNonce(agent.address);
  const commit = async (hash = TEST_STATE_HASH) => {
    const n = await nextNonce();
    await verifier.connect(agent).commitState(hash);
    return n;
  };
  const submit = (p, pl, n) => verifier.connect(agent).verifyAndExecute(p, pl, n);

  describe("commitState", function () {
    beforeEach(() => setup(0n));

    it("increments the agent nonce and stores the hash", async function () {
      const before = await nextNonce();
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      expect(await nextNonce()).to.equal(before + 1n);
      expect(await verifier.getPendingCommitment(agent.address, before)).to.equal(TEST_STATE_HASH);
    });
    it("records the block number of the commitment", async function () {
      const n = await commit();
      const c = await verifier.pendingCommitments(agent.address, n);
      expect(c.blockNumber).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    });
    it("reverts on a zero hash", async function () {
      await expect(verifier.connect(agent).commitState(ethers.ZeroHash)).to.be.revertedWith("RAV: zero state hash");
    });
    it("reverts on a hash outside the scalar field", async function () {
      await expect(verifier.connect(agent).commitState(ethers.zeroPadValue("0x" + "ff".repeat(32), 32)))
        .to.be.revertedWith("RAV: hash not in field");
    });
    it("reverts for non-agent callers", async function () {
      await expect(verifier.connect(outsider).commitState(TEST_STATE_HASH)).to.be.reverted;
    });
  });

  describe("happy path", function () {
    beforeEach(() => setup(0n));

    it("accepts a real Groth16 proof and executes the transfer", async function () {
      const n = await commit();
      const before = await token.balanceOf(TEST_RECIPIENT);
      await submit(VALID_PROOF, payload(), n);
      expect((await token.balanceOf(TEST_RECIPIENT)) - before).to.equal(TEST_AMOUNT);
    });
    it("rejects replay of the same commitment", async function () {
      const n = await commit();
      await submit(VALID_PROOF, payload(), n);
      await expect(submit(VALID_PROOF, payload(), n)).to.be.revertedWith("RAV: proof replayed");
    });
    it("rejects a modified proof for an already used commitment", async function () {
      // Groth16 proofs can be re-randomised into different valid-looking proofs for the
      // same statement. The nullifier is keccak256(agent, nonce) and ignores the proof
      // points, so a changed proof cannot produce a new nullifier. (This test changes a
      // point rather than building a true re-randomisation; the point is the nullifier.)
      const n = await commit();
      await submit(VALID_PROOF, payload(), n);
      const variant = JSON.parse(JSON.stringify(VALID_PROOF));
      variant.A.x = "0x" + (BigInt(variant.A.x) + 1n).toString(16);
      await expect(submit(variant, payload(), n)).to.be.revertedWith("RAV: proof replayed");
    });
  });

  describe("proof binding", function () {
    beforeEach(() => setup(0n));

    it("rejects a different token contract", async function () {
      const n = await commit();
      const other = ethers.getAddress("0x" + "11".repeat(20));
      await expect(submit(VALID_PROOF, payload({ token: other }), n)).to.be.revertedWith("RAV: proof invalid");
    });
    it("rejects a different deadline", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ deadline: TEST_DEADLINE + 1n }), n)).to.be.revertedWith("RAV: proof invalid");
    });
    it("rejects a different recipient", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ recipient: outsider.address }), n)).to.be.revertedWith("RAV: proof invalid");
    });
    it("rejects a different amount", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ amount: TEST_AMOUNT - 1n }), n)).to.be.revertedWith("RAV: proof invalid");
    });
    it("rejects a proof checked against a different commitment", async function () {
      const altered = ethers.zeroPadValue("0x" + (BigInt(S_H) ^ 1n).toString(16), 32);
      const n = await commit(altered);
      await expect(submit(VALID_PROOF, payload(), n)).to.be.revertedWith("RAV: proof invalid");
    });
    it("rejects a tampered proof point", async function () {
      const n = await commit();
      const bad = JSON.parse(JSON.stringify(VALID_PROOF));
      bad.C.x = "0x" + (BigInt(bad.C.x) + 1n).toString(16);
      await expect(submit(bad, payload(), n)).to.be.reverted;
    });
    it("rejects an input equal to the true value plus the field order", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ maxSlippageBps: TEST_SLIPPAGE_BPS + FIELD_R }), n)).to.be.reverted;
    });
  });

  describe("commitmentDelay (enforced on-chain)", function () {
    beforeEach(() => setup(5n));

    it("rejects a proof submitted before the delay has passed", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload(), n)).to.be.revertedWith("RAV: commitment too recent");
    });
    it("accepts the proof once enough blocks have been mined", async function () {
      const n = await commit();
      await hre.network.provider.send("hardhat_mine", ["0x5"]);
      await expect(submit(VALID_PROOF, payload(), n)).to.not.be.reverted;
    });
  });

  describe("policy rejections", function () {
    beforeEach(() => setup(0n));

    it("rejects expired payloads", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ deadline: 1000n }), n)).to.be.revertedWith("RAV: payload expired");
    });
    it("rejects a transfer above the cap", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ amount: MAX_TRANSFER_CAP + 1n }), n)).to.be.revertedWith("RAV: amount out of bounds");
    });
    it("rejects slippage above 100 percent", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ maxSlippageBps: 10001n }), n)).to.be.revertedWith("RAV: slippage exceeds 100%");
    });
    it("rejects a router that is not whitelisted", async function () {
      const n = await commit();
      await expect(submit(VALID_PROOF, payload({ routerHash: ethers.keccak256(ethers.toUtf8Bytes("x")) }), n))
        .to.be.revertedWith("RAV: router not whitelisted");
    });
  });

  describe("emergency controls", function () {
    beforeEach(() => setup(0n));

    it("guardian can pause and unpause", async function () {
      await verifier.connect(guardian).pause();
      expect(await verifier.paused()).to.be.true;
      await expect(verifier.connect(agent).commitState(TEST_STATE_HASH)).to.be.reverted;
      await verifier.connect(guardian).unpause();
      expect(await verifier.paused()).to.be.false;
    });
    it("emergency withdraw works when paused", async function () {
      await verifier.connect(guardian).pause();
      const bal = await token.balanceOf(await verifier.getAddress());
      const before = await token.balanceOf(owner.address);
      await verifier.emergencyWithdraw(TEST_TOKEN, owner.address, bal);
      expect((await token.balanceOf(owner.address)) - before).to.equal(bal);
    });
  });
});

describe("Baseline (SimpleGuard, no proof) versus ZKP-RA", function () {
  // Scenario: the agent's memory is altered after it started reasoning, and it
  // emits a transfer that satisfies every plain on-chain rule (under the cap,
  // whitelisted router, in time). Plain checks cannot tell this from an honest
  // transfer. ZKP-RA cannot produce a valid proof for a state that does not
  // match the committed hash (see scripts/benchmark/tamper_test.cjs).
  it("SimpleGuard accepts an in-policy transfer that a tampered agent produced", async function () {
    const [owner, agent] = await ethers.getSigners();
    const G = await ethers.getContractFactory("SimpleGuard");
    const guard = await G.deploy(MAX_TRANSFER_CAP);
    await guard.waitForDeployment();
    await guard.grantRole(await guard.AGENT_ROLE(), agent.address);
    await guard.setRouterWhitelist(TEST_ROUTER_HASH, true);
    const token = await deployToken(await guard.getAddress());
    const attacker = ethers.getAddress("0x" + "ab".repeat(20));
    const before = await token.balanceOf(attacker);
    const tx = await guard.connect(agent).execute(TEST_TOKEN, attacker, TEST_AMOUNT, 50, TEST_ROUTER_HASH, TEST_DEADLINE);
    const receipt = await tx.wait();
    expect((await token.balanceOf(attacker)) - before).to.equal(TEST_AMOUNT);
    console.log("      SimpleGuard execute gas:", receipt.gasUsed.toString());
  });
});
