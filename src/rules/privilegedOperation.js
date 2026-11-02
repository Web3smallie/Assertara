/**
 * Privileged-operation detection (Capability 4, B2).
 *
 * Ownership, upgrade, admin, role, and pause functions change who
 * controls a contract — a different risk class from moving tokens.
 * Matching is scoped by (standard, functionName) from signature-exact
 * decoding: a same-named function with a different signature never
 * matches, and bare function names are never trusted.
 *
 * Every finding names the affected contract, the caller (when the
 * transaction supplies `from`), and the account gaining or losing
 * authority, so the investigator can state WHO changes WHAT over
 * WHICH contract. Whether the caller is actually authorized to make
 * the call is NOT established here — on-chain authorization is
 * outside calldata — and each description says so where relevant.
 */

function callerOf(decodedTx) {
  const s = decodedTx && typeof decodedTx.sender === 'string' ? decodedTx.sender.toLowerCase() : null;
  return s || 'unknown caller';
}

function addr(v) {
  return typeof v === 'string' ? v.toLowerCase() : null;
}

function evaluatePrivilegedOperation(decodedTx) {
  const fn = decodedTx && decodedTx.functionName;
  const standard = decodedTx && decodedTx.standard;
  const params = (decodedTx && decodedTx.parameters) || {};
  const contract = decodedTx && decodedTx.contract ? decodedTx.contract : 'unknown contract';
  const caller = callerOf(decodedTx);

  if (standard === 'ProxyAdmin' && (fn === 'upgradeTo' || fn === 'upgradeToAndCall')) {
    const impl = addr(params.newImplementation);
    const withCall = fn === 'upgradeToAndCall';
    return {
      ruleId: 'PROXY_UPGRADE',
      severity: 'CRITICAL',
      description: `Transaction upgrades proxy ${contract} to implementation ${impl || '(unparsed)'}${withCall ? ' with an immediate post-upgrade call' : ''}, replacing ALL of its behavior. The caller (${caller}) must hold upgrade authority or the call reverts; authorization itself is not verified here.`,
      triggered: true,
      metadata: { proxy: contract, newImplementation: impl, caller, withCall }
    };
  }
  if (standard === 'ProxyAdmin' && fn === 'changeAdmin') {
    const admin = addr(params.newAdmin);
    return {
      ruleId: 'PROXY_ADMIN_CHANGE',
      severity: 'CRITICAL',
      description: `Transaction transfers upgrade authority over proxy ${contract} to ${admin || '(unparsed)'}. The new admin can replace the implementation at will. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { proxy: contract, newAdmin: admin, caller }
    };
  }
  if (standard === 'Ownable' && fn === 'transferOwnership') {
    const owner = addr(params.newOwner);
    return {
      ruleId: 'OWNERSHIP_TRANSFER',
      severity: 'HIGH',
      description: `Transaction transfers ownership of ${contract} to ${owner || '(unparsed)'}. The new owner gains all owner-only authority. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, newOwner: owner, caller }
    };
  }
  if (standard === 'Ownable' && fn === 'renounceOwnership') {
    return {
      ruleId: 'OWNERSHIP_RENOUNCED',
      severity: 'MEDIUM',
      description: `Transaction renounces ownership of ${contract}: owner-only functions become permanently uncallable. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, caller }
    };
  }
  if (standard === 'AccessControl' && fn === 'grantRole') {
    const account = addr(params.account);
    return {
      ruleId: 'ROLE_GRANTED',
      severity: 'HIGH',
      description: `Transaction grants role ${params.role || '(unparsed)'} on ${contract} to ${account || '(unparsed)'}. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, role: params.role || null, account, caller }
    };
  }
  if (standard === 'AccessControl' && fn === 'revokeRole') {
    const account = addr(params.account);
    return {
      ruleId: 'ROLE_REVOKED',
      severity: 'MEDIUM',
      description: `Transaction revokes role ${params.role || '(unparsed)'} on ${contract} from ${account || '(unparsed)'}. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, role: params.role || null, account, caller }
    };
  }
  if (standard === 'AccessControl' && fn === 'renounceRole') {
    const account = addr(params.account);
    return {
      ruleId: 'ROLE_RENOUNCED',
      severity: 'MEDIUM',
      description: `Transaction renounces role ${params.role || '(unparsed)'} on ${contract} for ${account || '(unparsed)'}. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, role: params.role || null, account, caller }
    };
  }
  if (standard === 'Pausable' && fn === 'pause') {
    return {
      ruleId: 'CONTRACT_PAUSED',
      severity: 'MEDIUM',
      description: `Transaction pauses ${contract}: guarded functions become unusable until unpaused. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, caller }
    };
  }
  if (standard === 'Pausable' && fn === 'unpause') {
    return {
      ruleId: 'CONTRACT_UNPAUSED',
      severity: 'MEDIUM',
      description: `Transaction unpauses ${contract}: previously guarded functions become usable again. Caller: ${caller} (authorization not verified here).`,
      triggered: true,
      metadata: { contract, caller }
    };
  }
  return null;
}

module.exports = { evaluatePrivilegedOperation };
