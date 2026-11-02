/**
 * Simulation evidence for investigation (Capability 3, B2). Corrects the
 * ordering fault where simulation ran after reasoning and could never
 * inform it: deterministic triggers run simulation BEFORE the model call,
 * and a deterministic reconciliation compares measured execution against
 * decoded expectations afterwards.
 *
 * Honesty core: only `executed/success/escalationDetected` are measured
 * EVM observations. Asset deltas and fallback analyses are decode-derived
 * labels, never measurements, and are marked as such everywhere.
 */

const { simulateTransactionWithFoundry } = require('./simulatorService');

function shouldSimulatePreReasoning(decodedTx) {
  if (!decodedTx || typeof decodedTx !== 'object') return false;
  if (decodedTx.isUnlimitedApproval === true) return true;
  if (Array.isArray(decodedTx.ruleFindings)
      && decodedTx.ruleFindings.some((r) => r && (r.severity === 'HIGH' || r.severity === 'CRITICAL'))) {
    return true;
  }
  if (decodedTx.standard === 'Unknown' || decodedTx.functionName === 'unknownFunction') return true;
  return false;
}

function isApprovalFn(fn) {
  return fn === 'approve' || fn === 'increaseAllowance' || fn === 'setApprovalForAll';
}

async function runSimulationEvidence({ transaction, decodedTx }) {
  const raw = await simulateTransactionWithFoundry({
    from: transaction && transaction.from,
    to: transaction && transaction.to,
    data: transaction && transaction.data,
    decodedTx
  });
  const evidence = {
    simId: 'SIM-001',
    status: raw.status || 'UNKNOWN',
    executed: raw.executed === true,
    success: raw.success === true ? true : raw.executed === true ? false : null,
    escalationDetected: raw.escalationDetected === true,
    error: typeof raw.error === 'string' ? raw.error.slice(0, 300) : null,
    reason: typeof raw.reason === 'string' ? raw.reason.slice(0, 300) : null,
    mode: raw.mode || null,
    measuredNote: 'measured: executed/success/escalationDetected only; deltas are decode-derived'
  };
  return { evidence, raw };
}

function notRunEvidence() {
  return {
    simId: 'SIM-001', status: 'NOT_RUN', executed: false, success: null,
    escalationDetected: false, error: null,
    reason: 'Simulation not requested for this investigation.',
    mode: 'not-run', measuredNote: 'nothing measured'
  };
}

// Deterministic reconciliation of measured simulation against decoded
// expectations. Conservative by design: only measured contradictions
// downgrade; FAILED/FALLBACK/NOT_RUN never move anything (a failed sim
// is not safety evidence, and not danger evidence either).
function reconcileSimulation({ sim, decodedTx }) {
  const noEffect = (reason) => ({ status: 'NOT_APPLICABLE', downgrade: false, reason, rule: null });
  if (!sim || typeof sim !== 'object') return noEffect('no simulation record');
  if (sim.status === 'NOT_RUN' || sim.status === 'FALLBACK' || sim.status === 'FAILED') {
    return { status: 'INCONCLUSIVE', downgrade: false, reason: `simulation ${sim.status}: no measured execution to reconcile`, rule: null };
  }
  if (sim.executed !== true) return noEffect('simulation did not execute');
  if (sim.success === false) {
    return {
      status: 'CONTRADICT', downgrade: true, rule: 'SIM_EXECUTION_FAILED',
      reason: 'Measured EVM execution reverted; a MATCH verdict cannot stand on a reverting transaction.'
    };
  }
  if (sim.escalationDetected === true && !isApprovalFn(decodedTx && decodedTx.functionName)) {
    return {
      status: 'CONTRADICT', downgrade: true, rule: 'SIM_UNEXPECTED_ALLOWANCE',
      reason: 'Measured allowance escalation on a non-approval call; decoded operation disagrees with execution.'
    };
  }
  return { status: 'AGREE', downgrade: false, reason: 'Measured execution consistent with decoded expectations.', rule: null };
}

module.exports = {
  shouldSimulatePreReasoning,
  runSimulationEvidence,
  notRunEvidence,
  reconcileSimulation
};
