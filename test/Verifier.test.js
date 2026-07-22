/**
 * Verifier.test.js — Integration tests for ReasoningAnchorVerifier
 *
 * Tests the full ZKP-RA pipeline:
 *   1. commitState() anchors H_t on-chain.
 *   2. verifyAndExecute() with a valid Groth16 proof releases ERC-20 transfer.
 *   3. Replay, expired, and policy-violating proofs are rejected.
 *
 * VALID_PROOF/public signals below are a real Groth16 proof generated
 * end-to-end with snarkjs against circuits/reasoning_anchor.circom (see
 * build/gen_input.cjs and build/bench.cjs), against the dev/benchmark
 * trusted-setup ceremony whose verification key is hardcoded in
 * contracts/Verifier.sol. Regenerate both together if either the circuit
 * or the ceremony changes.
 */

const { expect } = require("chai");
const hre = require("hardhat");
const { ethers } = hre;

const VALID_PROOF = {
  A: {
    x: "0x124db2b11428c7d24916ca8394b51eb8be31cb09aaa7408ac49def6aff9f7a3",
    y: "0x28c81058bced616f0d94e970e489d501ad5f833b277d8e62907cddad4b4b0326",
  },
  B: {
    x: [
      "0x251e36fe2e52d9c0585602bff57d566262ddb5e2523e4c92a1ae63bc0c7ee444",
      "0x70458673d8ef170b6695bd7beb519de827fdc1f713425443ed34857dd373cdb",
    ],
    y: [
      "0xb90086e9cb8a3c772448fd98cdd8ecaf6e5c0d0aae29287af9679d7549f4cf8",
      "0x18c0a9874eec97c2579b04df681af7f2c6981e45bb880f023d11bec8104eb96d",
    ],
  },
  C: {
    x: "0x1cd5e1070d2c883fa8c12059f39774de10dc0045543e44ed9003e0cde248a734",
    y: "0x21968cead576fb974dfce78c4bd72797b5f1939a48a6698ea5c1d65222c47584",
  },
};

// Public signals, in circuit order [H_t, tx_recipient, tx_amount, tx_slippage_bps, tx_router_hash]
const TEST_STATE_HASH =
  "0x1c43f121168a5b78d24c5145f83b85a6ac052401e4fb40a1b5b83699746d7185";
const TEST_RECIPIENT = ethers.getAddress("0x" + (999).toString(16).padStart(40, "0"));
const TEST_AMOUNT = 500000000000000000000n; // 500 tokens (18 decimals)
const TEST_SLIPPAGE_BPS = 50n;
const TEST_ROUTER_HASH =
  "0x1914879b2a4e7f9555f3eb55837243cefb1366a692794a7e5b5b3181fb14b49b";

const MAX_TRANSFER_CAP = ethers.parseEther("1000000");
const COMMITMENT_DELAY = 0n; // no delay in tests

describe("ReasoningAnchorVerifier", function () {
  let verifier, token, owner, agent, recipient, guardian;

  beforeEach(async function () {
    [owner, agent, recipient, guardian] = await ethers.getSigners();

    const VerifierFactory = await ethers.getContractFactory("ReasoningAnchorVerifier");
    verifier = await VerifierFactory.deploy(MAX_TRANSFER_CAP, COMMITMENT_DELAY);
    await verifier.waitForDeployment();

    const ERC20Factory = await ethers.getContractFactory("MockERC20");
    token = await ERC20Factory.deploy("TestToken", "TT");
    await token.waitForDeployment();
    await token.mint(await verifier.getAddress(), ethers.parseEther("10000000"));

    const AGENT_ROLE = await verifier.AGENT_ROLE();
    const GUARDIAN_ROLE = await verifier.GUARDIAN_ROLE();
    await verifier.grantRole(AGENT_ROLE, agent.address);
    await verifier.grantRole(GUARDIAN_ROLE, guardian.address);

    await verifier.connect(guardian).setRouterWhitelist(TEST_ROUTER_HASH, true);
  });

  describe("commitState", function () {
    it("increments agent nonce and stores hash", async function () {
      const nonceBefore = await verifier.agentNonce(agent.address);
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const nonceAfter = await verifier.agentNonce(agent.address);
      expect(nonceAfter).to.equal(nonceBefore + 1n);

      const stored = await verifier.getPendingCommitment(agent.address, nonceBefore);
      expect(stored).to.equal(TEST_STATE_HASH);
    });

    it("reverts on zero state hash", async function () {
      await expect(
        verifier.connect(agent).commitState(ethers.ZeroHash)
      ).to.be.revertedWith("RAV: zero state hash");
    });

    it("reverts for non-agent callers", async function () {
      await expect(
        verifier.connect(recipient).commitState(TEST_STATE_HASH)
      ).to.be.reverted;
    });
  });

  describe("verifyAndExecute — happy path", function () {
    it("accepts a real Groth16 proof and executes the ERC-20 transfer", async function () {
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const payload = buildDefaultPayload(token);

      const balBefore = await token.balanceOf(TEST_RECIPIENT);
      await submitProof(verifier, agent, VALID_PROOF, payload, 0n);
      const balAfter = await token.balanceOf(TEST_RECIPIENT);

      expect(balAfter - balBefore).to.equal(TEST_AMOUNT);
    });

    it("rejects proof replay", async function () {
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const payload = buildDefaultPayload(token);

      await submitProof(verifier, agent, VALID_PROOF, payload, 0n);
      await expect(
        submitProof(verifier, agent, VALID_PROOF, payload, 0n)
      ).to.be.revertedWith("RAV: proof replayed");
    });
  });

  describe("verifyAndExecute — policy rejections", function () {
    it("rejects expired payloads", async function () {
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const deadline = Math.floor(Date.now() / 1000) - 100;
      const payload = { ...buildDefaultPayload(token), deadline };
      await expect(
        submitProof(verifier, agent, VALID_PROOF, payload, 0n)
      ).to.be.revertedWith("RAV: payload expired");
    });

    it("rejects transfer exceeding cap", async function () {
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const payload = { ...buildDefaultPayload(token), amount: MAX_TRANSFER_CAP + 1n };
      await expect(
        submitProof(verifier, agent, VALID_PROOF, payload, 0n)
      ).to.be.revertedWith("RAV: amount out of bounds");
    });

    it("rejects slippage above 100%", async function () {
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const payload = { ...buildDefaultPayload(token), maxSlippageBps: 10_001 };
      await expect(
        submitProof(verifier, agent, VALID_PROOF, payload, 0n)
      ).to.be.revertedWith("RAV: slippage exceeds 100%");
    });

    it("rejects non-whitelisted router", async function () {
      await verifier.connect(agent).commitState(TEST_STATE_HASH);
      const payload = {
        ...buildDefaultPayload(token),
        routerHash: ethers.keccak256(ethers.toUtf8Bytes("not-whitelisted")),
      };
      await expect(
        submitProof(verifier, agent, VALID_PROOF, payload, 0n)
      ).to.be.revertedWith("RAV: router not whitelisted");
    });
  });

  describe("emergency controls", function () {
    it("guardian can pause and unpause", async function () {
      await verifier.connect(guardian).pause();
      expect(await verifier.paused()).to.be.true;
      await expect(
        verifier.connect(agent).commitState(TEST_STATE_HASH)
      ).to.be.reverted;
      await verifier.connect(guardian).unpause();
      expect(await verifier.paused()).to.be.false;
    });

    it("emergency withdraw works when paused", async function () {
      await verifier.connect(guardian).pause();
      const bal = await token.balanceOf(await verifier.getAddress());
      await verifier.emergencyWithdraw(await token.getAddress(), owner.address, bal);
      expect(await token.balanceOf(owner.address)).to.equal(bal);
      await verifier.connect(guardian).unpause();
    });
  });
});

function futureDeadline() {
  return Math.floor(Date.now() / 1000) + 3600;
}

function buildDefaultPayload(token) {
  return {
    token: token.target,
    recipient: TEST_RECIPIENT,
    amount: TEST_AMOUNT,
    maxSlippageBps: TEST_SLIPPAGE_BPS,
    routerHash: TEST_ROUTER_HASH,
    deadline: futureDeadline(),
  };
}

function computeNullifier(proof, agent, nonce) {
  return ethers.solidityPackedKeccak256(
    ["uint256", "uint256", "address", "uint256"],
    [proof.A.x, proof.A.y, agent, nonce]
  );
}

async function submitProof(verifier, agent, proof, payload, commitNonce) {
  const nullifier = computeNullifier(proof, agent.address, commitNonce);
  return verifier.connect(agent).verifyAndExecute(proof, payload, commitNonce, nullifier);
}
