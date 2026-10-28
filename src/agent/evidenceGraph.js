/**
 * Assertara Evidence Graph — append-only, application-controlled evidence store.
 * The orchestrator mints every ID. The model may propose relationships, but only
 * validated nodes/edges enter the graph. Nothing here calls the network.
 */

const crypto = require('crypto');

const EDGE_TYPES = ['SUPPORTS', 'CONTRADICTS', 'REFINES', 'SUPERSEDES', 'DERIVED_FROM'];
const PRODUCERS = ['USER', 'TOOL', 'MODEL'];

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

class EvidenceGraph {
  constructor(investigationId) {
    this.investigationId = investigationId;
    this.nodes = new Map();
    this.edges = [];
    this.seq = 0;
  }

  mintId() {
    this.seq += 1;
    return `E-${String(this.seq).padStart(3, '0')}`;
  }

  /**
   * @param {object} node { kind, producer, payload, tool_ref?, input_hashes?, created_turn?, supersedes? }
   * @returns stored node with id
   */
  append(node) {
    if (!node || typeof node !== 'object') throw new Error('evidence node must be an object');
    if (!node.kind || typeof node.kind !== 'string') throw new Error('evidence node requires a string kind');
    if (!PRODUCERS.includes(node.producer)) throw new Error(`evidence producer must be one of ${PRODUCERS.join(',')}`);
    if (node.tool_ref !== undefined && typeof node.tool_ref !== 'string') {
      throw new Error('evidence tool_ref must be a string');
    }
    if (node.supersedes !== undefined && !this.nodes.has(node.supersedes)) {
      throw new Error(`supersedes references unknown node ${node.supersedes}`);
    }
    const stored = {
      id: this.mintId(),
      kind: node.kind,
      producer: node.producer,
      tool_ref: node.tool_ref || null,
      input_hashes: Array.isArray(node.input_hashes) ? node.input_hashes.slice() : [],
      payload: node.payload === undefined ? null : node.payload,
      created_turn: Number.isInteger(node.created_turn) ? node.created_turn : 0
    };
    if (node.supersedes) stored.supersedes = node.supersedes;
    this.nodes.set(stored.id, stored);
    return stored;
  }

  relate(fromId, type, toId) {
    if (!this.nodes.has(fromId)) throw new Error(`unknown evidence node ${fromId}`);
    if (!this.nodes.has(toId)) throw new Error(`unknown evidence node ${toId}`);
    if (!EDGE_TYPES.includes(type)) throw new Error(`edge type must be one of ${EDGE_TYPES.join(',')}`);
    const edge = { from: fromId, type, to: toId };
    this.edges.push(edge);
    return edge;
  }

  has(id) {
    return this.nodes.has(id);
  }

  get(id) {
    return this.nodes.get(id) || null;
  }

  /**
   * Validate that every id in `ids` exists. Returns { ok, unknown[] }.
   * Never throws on unknown ids — callers decide how to handle them.
   */
  validateRefs(ids) {
    const unknown = [];
    for (const id of ids || []) {
      if (!this.nodes.has(id)) unknown.push(id);
    }
    return { ok: unknown.length === 0, unknown };
  }

  byKind(kind) {
    return [...this.nodes.values()].filter((n) => n.kind === kind);
  }

  edgesFrom(id, type) {
    return this.edges.filter((e) => e.from === id && (!type || e.type === type));
  }

  edgesTo(id, type) {
    return this.edges.filter((e) => e.to === id && (!type || e.type === type));
  }

  export() {
    return {
      investigationId: this.investigationId,
      nodes: [...this.nodes.values()],
      edges: this.edges.map((e) => ({ ...e }))
    };
  }
}

module.exports = { EvidenceGraph, EDGE_TYPES, PRODUCERS, sha256Hex };
