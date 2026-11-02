/**
 * Assertara autonomous agent (public surface).
 *
 * The agent is architecturally independent of Assertara's internals: it
 * may import the public SDK, the shared digest helper, and Node
 * builtins only (enforced by test/unit/agentBoundary.test.js). All
 * investigation, decision, approval, and signing authority lives on
 * the Assertara side of the SDK boundary.
 */

const { createAutonomousAgent } = require('./runtime/agent');

module.exports = { createAutonomousAgent };
