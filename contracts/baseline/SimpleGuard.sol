// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SimpleGuard
 * @notice Baseline used in the paper's comparison. It enforces the same plain
 *         on-chain policy as ZKP-RA (amount cap, router whitelist, deadline)
 *         but has no state commitment and no proof. Anything that a contract
 *         can check by looking at the transaction alone is checked here; the
 *         only thing it cannot check is whether the agent's memory was
 *         tampered with after the agent started reasoning.
 */
contract SimpleGuard is AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public maxTransferCap;
    mapping(bytes32 => bool) public whitelistedRouterHashes;

    constructor(uint256 _maxTransferCap) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        maxTransferCap = _maxTransferCap;
    }

    function setRouterWhitelist(bytes32 routerHash, bool status) external onlyRole(GUARDIAN_ROLE) {
        whitelistedRouterHashes[routerHash] = status;
    }

    function execute(
        address token,
        address recipient,
        uint256 amount,
        uint256 maxSlippageBps,
        bytes32 routerHash,
        uint256 deadline
    ) external onlyRole(AGENT_ROLE) {
        require(block.timestamp <= deadline, "SG: payload expired");
        require(amount > 0 && amount <= maxTransferCap, "SG: amount out of bounds");
        require(maxSlippageBps <= 200, "SG: slippage too high");
        require(whitelistedRouterHashes[routerHash], "SG: router not whitelisted");
        IERC20(token).safeTransfer(recipient, amount);
    }
}
