const hre = require("hardhat");
const fs = require("fs");

function hex(d) {
  return "0x" + BigInt(d).toString(16);
}

async function main() {
  const proof = JSON.parse(fs.readFileSync("build/proof.json", "utf8"));
  const pub = JSON.parse(fs.readFileSync("build/public.json", "utf8"));
  const [H_t, tx_recipient, tx_amount, tx_slippage_bps, tx_router_hash] = pub;

  const [owner, agentSigner, guardianSigner] = await hre.ethers.getSigners();

  const Token = await hre.ethers.getContractFactory("MockERC20");
  const token = await Token.deploy("TestToken", "TT");
  await token.waitForDeployment();

  const Verifier = await hre.ethers.getContractFactory("ReasoningAnchorVerifier");
  const verifier = await Verifier.deploy(
    hre.ethers.parseEther("1000000"), // maxTransferCap
    0 // commitmentDelay
  );
  await verifier.waitForDeployment();

  await token.mint(await verifier.getAddress(), hre.ethers.parseEther("1000000"));

  const AGENT_ROLE = await verifier.AGENT_ROLE();
  const GUARDIAN_ROLE = await verifier.GUARDIAN_ROLE();
  await verifier.grantRole(AGENT_ROLE, agentSigner.address);
  await verifier.grantRole(GUARDIAN_ROLE, guardianSigner.address);

  const routerHashBytes32 = hex(tx_router_hash);
  await verifier.connect(guardianSigner).setRouterWhitelist(routerHashBytes32, true);

  // ---- Phase 1: commitState ----
  const commitTx = await verifier.connect(agentSigner).commitState(hex(H_t));
  const commitReceipt = await commitTx.wait();
  const commitNonce = 0n;

  // The proof's public input for tx_recipient is the fixed test value 999
  // (see build/gen_input.cjs). The contract recomputes pubInputs[1] as
  // uint256(uint160(tx_.recipient)) and feeds it into the same pairing
  // check, so the payload's recipient address must equal address(999) for
  // the SNARK's committed public input to match what the contract derives.
  const recipientAddr = hre.ethers.getAddress(
    "0x" + (999).toString(16).padStart(40, "0")
  );

  const payload = {
    token: await token.getAddress(),
    recipient: recipientAddr,
    amount: BigInt(tx_amount),
    maxSlippageBps: BigInt(tx_slippage_bps),
    routerHash: routerHashBytes32,
    deadline: Math.floor(Date.now() / 1000) + 3600,
  };

  const solProof = {
    A: { x: hex(proof.pi_a[0]), y: hex(proof.pi_a[1]) },
    B: {
      x: [hex(proof.pi_b[0][1]), hex(proof.pi_b[0][0])],
      y: [hex(proof.pi_b[1][1]), hex(proof.pi_b[1][0])],
    },
    C: { x: hex(proof.pi_c[0]), y: hex(proof.pi_c[1]) },
  };

  const nullifier = hre.ethers.solidityPackedKeccak256(
    ["uint256", "uint256", "address", "uint256"],
    [solProof.A.x, solProof.A.y, agentSigner.address, commitNonce]
  );

  const tx = await verifier
    .connect(agentSigner)
    .verifyAndExecute(solProof, payload, commitNonce, nullifier);
  const receipt = await tx.wait();

  console.log("=== REAL ON-CHAIN MEASUREMENT ===");
  console.log("commitState gas:", commitReceipt.gasUsed.toString());
  console.log("verifyAndExecute gas:", receipt.gasUsed.toString());
  console.log("status:", receipt.status === 1 ? "SUCCESS" : "FAILED");

  const bal = await token.balanceOf(recipientAddr);
  console.log("recipient balance after transfer:", bal.toString());
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
