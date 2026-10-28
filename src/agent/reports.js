/**
 * Assertara shared reporting — typed builders over the evidence graph and
 * execution ledger. Reports cite evidence IDs; replay bundles carry inputs,
 * graph, versions, and ledger so a third party can re-run deterministic parts.
 */

const TOOL_VERSIONS = {
  decoder: 'decoderService:viem-2.x',
  simulator: 'simulatorService:forge-exec',
  sam: 'samService:responses-sam-3-1',
  ocr: 'ocrService:tesseract',
  orchestrator: 'agent:orchestrator-v1'
};

function buildInvestigationReport({ record, graph, verdict, findings, unknowns }) {
  if (!record || !graph) throw new Error('report requires a record and graph');
  return {
    type: 'InvestigationReport',
    investigationId: record.id,
    featureId: record.feature,
    status: record.status,
    stopReason: record.stopReason,
    verdict: verdict || null,
    findings: (findings || []).map((f) => ({
      id: f.id,
      claim: f.claim,
      severity: f.severity || 'INFO',
      confidence: f.confidence === undefined ? null : f.confidence,
      supporting: f.supporting || [],
      contradicting: f.contradicting || [],
      verification: f.verification || { status: 'HYPOTHESIS', reasons: ['unreviewed'] },
      unknowns: f.unknowns || [],
      recommendedAction: f.recommendedAction || null
    })),
    unknowns: unknowns || [],
    ledger: { ...record.ledger },
    graph: graph.export()
  };
}

function buildReplayBundle({ record, graph }) {
  if (!record || !graph) throw new Error('replay bundle requires a record and graph');
  return {
    type: 'ReplayBundle',
    version: 1,
    investigationId: record.id,
    featureId: record.feature,
    inputs: record.inputs,
    turns: record.turns,
    graph: graph.export(),
    ledger: { ...record.ledger },
    toolVersions: { ...TOOL_VERSIONS },
    note: 'Deterministic tools (decode, compare, checks) can be re-executed from inputs. Model turns and external data are recorded history, not re-runnable guarantees.'
  };
}

function buildTranslatorOutput({ decoded, explanation, risks, unknowns }) {
  if (!decoded) throw new Error('translator output requires decoded transaction facts');
  return {
    type: 'TranslatorOutput',
    action: explanation.action || null,
    assets: explanation.assets || [],
    contract: explanation.contract || null,
    permissions: explanation.permissions || null,
    boundedOrUnlimited: explanation.boundedOrUnlimited || null,
    consequences: explanation.consequences || [],
    risks: risks || [],
    unknowns: unknowns || [],
    verifiedAgainst: {
      function: decoded.functionName || null,
      contract: decoded.contract || null,
      parameters: decoded.parameters || {}
    }
  };
}

module.exports = { buildInvestigationReport, buildReplayBundle, buildTranslatorOutput, TOOL_VERSIONS };
