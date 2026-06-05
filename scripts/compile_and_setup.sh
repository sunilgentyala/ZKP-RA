#!/usr/bin/env bash
# compile_and_setup.sh
# Compiles the reasoning_anchor circuit, runs the powers-of-tau ceremony
# (Phase 1 from Hermez's bn128 ptau files), and generates the proving/
# verification keys. Requires: circom 2.1.6, snarkjs 0.7.4, Node 20+.

set -euo pipefail

CIRCUIT="circuits/reasoning_anchor"
PTAU="powersOfTau28_hez_final_15.ptau"
PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau"
BUILD_DIR="build"

mkdir -p "$BUILD_DIR"

echo "[1/6] Downloading Powers-of-Tau (Phase 1) if not cached..."
if [ ! -f "$PTAU" ]; then
    curl -L "$PTAU_URL" -o "$PTAU"
fi

echo "[2/6] Compiling circuit to r1cs + wasm..."
circom "${CIRCUIT}.circom" \
    --r1cs --wasm --sym --json \
    -l node_modules \
    -o "$BUILD_DIR"

echo "[3/6] Phase 2 setup (circuit-specific trusted setup)..."
snarkjs groth16 setup \
    "${BUILD_DIR}/reasoning_anchor.r1cs" \
    "$PTAU" \
    "${BUILD_DIR}/reasoning_anchor_0.zkey"

echo "[4/6] Contribute entropy to Phase 2 ceremony..."
echo "zkp-ra-entropy-$(date +%s)-$(head -c 32 /dev/urandom | base64)" | \
    snarkjs zkey contribute \
    "${BUILD_DIR}/reasoning_anchor_0.zkey" \
    "${BUILD_DIR}/reasoning_anchor_final.zkey" \
    --name="ZKP-RA Dev Contribution" -v

echo "[5/6] Export verification key..."
snarkjs zkey export verificationkey \
    "${BUILD_DIR}/reasoning_anchor_final.zkey" \
    "${BUILD_DIR}/verification_key.json"

echo "[6/6] Export Solidity verifier (reference, not used in production)..."
snarkjs zkey export solidityverifier \
    "${BUILD_DIR}/reasoning_anchor_final.zkey" \
    "${BUILD_DIR}/SnarkJSVerifier_reference.sol"

echo ""
echo "Build complete. Artifacts in ${BUILD_DIR}/"
echo "  Proving key:      ${BUILD_DIR}/reasoning_anchor_final.zkey"
echo "  WASM circuit:     ${BUILD_DIR}/reasoning_anchor_js/reasoning_anchor.wasm"
echo "  Verification key: ${BUILD_DIR}/verification_key.json"
echo ""
echo "IMPORTANT: For production, replace the IC values in contracts/Verifier.sol"
echo "with the output of: snarkjs vkey --verificationkey ${BUILD_DIR}/verification_key.json"
