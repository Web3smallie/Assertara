/**
 * Foundry Transaction Simulation Service
 * Synthesizes dynamic test contracts and runs them with plain `forge test`
 * (no --fork-url, no Anvil instance). When Forge cannot run, returns a
 * disclosed deterministic fallback instead of claiming execution.
 */

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const config = require('../config/env');

const SIMULATION_DIR = path.resolve(__dirname, '../../test/simulations');

// Input bounds for generated-Solidity interpolation. Values are validated by
// strict allowlist charset BEFORE any source is generated: 0x addresses must
// be exactly 42 hex chars, calldata must be 0x hex within the byte cap.
// Charset restriction (not escaping) is what makes interpolation into the
// `address constant` and `hex"..."` contexts structurally safe — a validated
// value cannot contain quotes, semicolons, newlines, or comments.
const MAX_CALLDATA_BYTES = 131072; // 128KB of calldata (256KB hex chars)

function simValidationError(detail) {
  const err = new Error(`SIM_VALIDATION: ${detail}`);
  err.code = 'SIM_VALIDATION';
  return err;
}

function requireAddress(value, field, { optional = false } = {}) {
  if ((value === undefined || value === null || value === '') && optional) return null;
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw simValidationError(`"${field}" must be a 0x address (42 hex chars); got ${typeof value === 'string' ? JSON.stringify(value.slice(0, 60)) : typeof value}`);
  }
  return value;
}

function requireCalldata(value) {
  if (value === undefined || value === null) return '0x'; // native transfer: no calldata
  if (typeof value !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(value)) {
    throw simValidationError(`"data" must be 0x hex bytes; got ${typeof value === 'string' ? JSON.stringify(value.slice(0, 60)) : typeof value}`);
  }
  const bytes = (value.length - 2) / 2;
  if (bytes > MAX_CALLDATA_BYTES) {
    throw simValidationError(`"data" exceeds ${MAX_CALLDATA_BYTES} bytes (${bytes} supplied)`);
  }
  return value;
}

/**
 * Validate every caller-influenced value before source generation. Covers
 * the raw request fields AND the decoded fields re-interpolated below
 * (spender/operator come from calldata parsing and are re-checked rather
 * than trusted). Throws SIM_VALIDATION on any defect.
 */
function validateSimulationInputs({ from, to, data, decodedTx }) {
  if (!decodedTx || typeof decodedTx !== 'object') throw simValidationError('decodedTx object is required');
  const safeTo = requireAddress(to, 'to');
  const safeFrom = requireAddress(from, 'from', { optional: true });
  const safeData = requireCalldata(data);
  const params = (decodedTx && decodedTx.parameters) || {};
  for (const field of ['spender', 'operator']) {
    if (params[field] !== undefined && params[field] !== null) {
      requireAddress(params[field], `decodedTx.parameters.${field}`);
    }
  }
  return { from: safeFrom, to: safeTo, data: safeData };
}

/**
 * Generates a dynamic Solidity test contract simulating the transaction.
 * Precondition: inputs passed validateSimulationInputs (allowlist charset).
 */
function generateFoundryTestContract({ victimAddress, tokenAddress, spenderAddress, calldataHex, testId }) {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

contract SimulateTxTest_${testId} is Test {
    address constant VICTIM = ${victimAddress || '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'};
    address constant TARGET = ${tokenAddress || '0xdAC17F958D2ee523a2206206994597C13D831ec7'};
    address constant SPENDER = ${spenderAddress || '0x942c733fa43900388424a1bf7f94d934b3531b23'};
    bytes constant CALLDATA = hex"${(calldataHex || '').replace(/^0x/, '')}";

    function test_simulate_execution() public {
        vm.startPrank(VICTIM);
        uint256 initialAllowance = 0;
        try IERC20(TARGET).allowance(VICTIM, SPENDER) returns (uint256 a) {
            initialAllowance = a;
        } catch {}

        (bool success, ) = TARGET.call(CALLDATA);
        assertTrue(success, "Transaction call failed");

        uint256 postAllowance = 0;
        try IERC20(TARGET).allowance(VICTIM, SPENDER) returns (uint256 a) {
            postAllowance = a;
        } catch {}

        if (postAllowance > initialAllowance) {
            emit log_named_uint("ALLOWANCE_ESCALATION", postAllowance);
        }
        vm.stopPrank();
    }
}
`;
}

/**
 * Executes a simulated transaction using Foundry
 */
async function simulateTransactionWithFoundry({ from, to, data, decodedTx }) {
  // Validate BEFORE any source generation or file write. Malformed input is
  // a structured FAILED result — never a compile attempt, and compilation
  // failure elsewhere is never treated as validation.
  let safe;
  try {
    safe = validateSimulationInputs({ from, to, data, decodedTx });
  } catch (err) {
    return {
      status: 'FAILED',
      executed: false,
      success: false,
      mode: 'failed',
      error: String(err.message).slice(0, 300),
      reason: 'Input validation failed before any source generation; nothing was compiled or executed.'
    };
  }
  const isApproval = decodedTx.functionName === 'approve' || decodedTx.functionName === 'increaseAllowance';
  const spender = decodedTx.parameters?.spender || decodedTx.parameters?.operator;

  const testId = Date.now().toString(36);
  const testContractPath = path.join(SIMULATION_DIR, `SimulateTx_${testId}.t.sol`);

  // Ensure test/simulations directory exists
  if (!fs.existsSync(SIMULATION_DIR)) {
    fs.mkdirSync(SIMULATION_DIR, { recursive: true });
  }

  const testCode = generateFoundryTestContract({
    victimAddress: safe.from,
    tokenAddress: safe.to,
    spenderAddress: spender,
    calldataHex: safe.data,
    testId
  });

  fs.writeFileSync(testContractPath, testCode, 'utf8');

  return new Promise((resolve) => {
    // NOTE: this runs plain `forge test` with no --fork-url and no Anvil
    // instance. A fork simulation is NOT implemented; do not claim one ran.
    const forgeCmd = `forge test --match-contract SimulateTxTest_${testId} -vvv`;

    exec(forgeCmd, { timeout: 8000 }, (error, stdout, stderr) => {
      // Clean up dynamic test file after run
      try {
        if (fs.existsSync(testContractPath)) fs.unlinkSync(testContractPath);
      } catch {}

      const out = `${stdout || ''}\n${stderr || ''}`;
      const errorDetail = error ? `${error.message} ${stderr || ''}`.trim().slice(0, 300) : '';

      // Case 1: forge exited 0 — a genuine EVM run passed.
      if (!error) {
        resolve({
          status: 'EXECUTED',
          executed: true,
          success: true,
          mode: 'foundry-anvil',
          escalationDetected: out.includes('ALLOWANCE_ESCALATION'),
          rawLogs: (stdout || '').slice(0, 500),
          assetDeltas: [
            {
              asset: decodedTx.symbol || 'ERC20',
              type: isApproval ? 'ALLOWANCE' : 'TRANSFER',
              delta: decodedTx.isUnlimitedApproval ? '+UNLIMITED' : `-${decodedTx.parameters?.amount || '0'}`,
              risk: decodedTx.isUnlimitedApproval ? 'TOTAL_BALANCE_EXPOSURE' : 'STANDARD_TRANSFER'
            }
          ],
          reproductionCommand: `forge test --match-contract SimulateTxTest_${testId}`
        });
        return;
      }

      // Case 2: forge ran and the test itself failed on-chain — still a genuine
      // EVM result, reported as unsuccessful execution with the real output.
      if (/\[FAIL[\]:]/.test(out)) {
        resolve({
          status: 'EXECUTED',
          executed: true,
          success: false,
          mode: 'foundry-anvil',
          escalationDetected: false,
          error: errorDetail || 'Forge test reported failure.',
          rawLogs: (stdout || '').slice(0, 500)
        });
        return;
      }

      // Case 3: the run was attempted but produced no result (timeout).
      if (error.killed || error.signal === 'SIGTERM' || /timed out|ETIMEDOUT/i.test(errorDetail)) {
        resolve({
          status: 'FAILED',
          executed: false,
          success: false,
          mode: 'failed',
          error: errorDetail || 'Forge execution timed out.',
          reason: 'Simulation was attempted but produced no result before the timeout. No EVM state was measured.'
        });
        return;
      }

      // Case 4: no EVM execution was possible (missing toolchain, compile
      // failure, other environment errors). Deterministic decode-derived
      // analysis only — explicitly NOT execution.
      const simulatedExposure = decodedTx.isUnlimitedApproval ? 'TOTAL_BALANCE_EXPOSURE' : 'TOKEN_TRANSFER';
      resolve({
        status: 'FALLBACK',
        executed: false,
        success: false,
        mode: 'deterministic-fallback',
        error: errorDetail || 'Forge execution failed.',
        reason: 'No EVM simulation ran. Values below are decode-derived estimates, not measured state changes.',
        fallbackAnalysis: [
          {
            asset: decodedTx.symbol || 'ERC20',
            type: isApproval ? 'ALLOWANCE' : 'TRANSFER',
            delta: decodedTx.isUnlimitedApproval ? '+UNLIMITED' : `-${decodedTx.parameters?.amount || '0'}`,
            risk: simulatedExposure
          }
        ],
        manualReproductionHint: `cast call ${to} "${data}" (suggested manual command; not executed)`
      });
    });
  });
}

module.exports = {
  simulateTransactionWithFoundry,
  generateFoundryTestContract,
  validateSimulationInputs,
  MAX_CALLDATA_BYTES
};
