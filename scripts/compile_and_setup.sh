#!/usr/bin/env bash
# compile_and_setup.sh
# Compiles the reasoning_anchor circuit and runs a DEVELOPMENT trusted setup:
# a locally generated Phase 1 (2^14), then three Phase 2 contributions and a beacon.
# This is not a production ceremony. Requires: circom (2.1.6+), snarkjs 0.7.4, Node 20+.
# circom is looked up in ./bin/circom(.exe) first, then on PATH.

set -euo pipefail

CIRCUIT="circuits/reasoning_anchor"
BUILD_DIR="build"
PTAU="${BUILD_DIR}/pot14_final.ptau"
SNARKJS="npx snarkjs"

if [ -x "bin/circom.exe" ]; then CIRCOM="bin/circom.exe"; elif [ -x "bin/circom" ]; then CIRCOM="bin/circom"; else CIRCOM="circom"; fi

mkdir -p "$BUILD_DIR"

echo "[1/7] Phase 1 powers of tau (2^14, local, development only)..."
if [ ! -f "$PTAU" ]; then
    $SNARKJS powersoftau new bn128 14 "${BUILD_DIR}/pot14_0000.ptau"
    echo "zkp-ra-phase1-$(date +%s)-$(head -c 32 /dev/urandom | base64)" | \
        $SNARKJS powersoftau contribute "${BUILD_DIR}/pot14_0000.ptau" "${BUILD_DIR}/pot14_0001.ptau" --name="ZKP-RA dev phase 1"
    $SNARKJS powersoftau prepare phase2 "${BUILD_DIR}/pot14_0001.ptau" "$PTAU"
fi

echo "[2/7] Compiling circuit to r1cs + wasm..."
# The circuit includes "node_modules/circomlib/...", so the include root is the repo root.
"$CIRCOM" "${CIRCUIT}.circom" --r1cs --wasm --sym -l . -o "$BUILD_DIR"

echo "[3/7] Phase 2 setup..."
$SNARKJS groth16 setup "${BUILD_DIR}/reasoning_anchor.r1cs" "$PTAU" "${BUILD_DIR}/ra_0.zkey"

echo "[4/7] Three Phase 2 contributions..."
prev="${BUILD_DIR}/ra_0.zkey"
for i in 1 2 3; do
    head -c 48 /dev/urandom | base64 | \
        $SNARKJS zkey contribute "$prev" "${BUILD_DIR}/ra_${i}.zkey" --name="ZKP-RA dev contributor ${i}"
    prev="${BUILD_DIR}/ra_${i}.zkey"
done

echo "[5/7] Random beacon and verification..."
$SNARKJS zkey beacon "$prev" "${BUILD_DIR}/reasoning_anchor_final.zkey" \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 -n="ZKP-RA dev beacon"
$SNARKJS zkey verify "${BUILD_DIR}/reasoning_anchor.r1cs" "$PTAU" "${BUILD_DIR}/reasoning_anchor_final.zkey"
rm -f "${BUILD_DIR}"/ra_[0-3].zkey

echo "[6/7] Export verification key..."
$SNARKJS zkey export verificationkey "${BUILD_DIR}/reasoning_anchor_final.zkey" "${BUILD_DIR}/verification_key.json"

echo "[7/7] Solidity constants for contracts/Verifier.sol..."
node scripts/export_vk_solidity.cjs "${BUILD_DIR}/verification_key.json" > "${BUILD_DIR}/vk_body.txt"

echo ""
echo "Build complete. Artifacts in ${BUILD_DIR}/"
echo "  Proving key:      ${BUILD_DIR}/reasoning_anchor_final.zkey"
echo "  WASM circuit:     ${BUILD_DIR}/reasoning_anchor_js/reasoning_anchor.wasm"
echo "  Verification key: ${BUILD_DIR}/verification_key.json"
echo ""
echo "A new setup produces a NEW verification key. Paste ${BUILD_DIR}/vk_body.txt into"
echo "VerificationKey.load() in contracts/Verifier.sol (IC has 8 entries), then run:"
echo "  node scripts/benchmark/gen_input.cjs && node scripts/benchmark/make_fixture.cjs && npx hardhat test"
