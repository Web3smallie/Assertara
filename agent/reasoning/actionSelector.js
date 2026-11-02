/**
 * Action selector: pure next-step policy for a planned task.
 *
 * Rules (conservative execution):
 * - Placeholder actions (planner-reported gaps) stop the task as
 *   PLAN_INCOMPLETE and are never submitted.
 * - A BLOCK or UNCERTAIN outcome on any action stops the whole task:
 *   no modify-and-resubmit, no alternate route, no skipping ahead.
 * - Otherwise the next unexecuted action submits, in plan order.
 */

const { isPlaceholderAction } = require('../planner/planner');

function nextAction(plan, state) {
  const actions = (plan && Array.isArray(plan.actions) ? plan.actions : []);
  const done = (state && Number.isSafeInteger(state.executed) ? state.executed : 0);
  const lastDecision = state ? state.lastDecision : null;
  if (lastDecision === 'BLOCK' || lastDecision === 'UNCERTAIN') {
    return {
      kind: 'stop',
      stoppedReason: lastDecision === 'BLOCK'
        ? 'BLOCKED: proposal refused; task ends without execution or retry'
        : `HELD: decision ${lastDecision} authorizes nothing; task ends`
    };
  }
  if (done >= actions.length) return { kind: 'done' };
  const action = actions[done];
  if (isPlaceholderAction(action)) {
    return {
      kind: 'stop',
      stoppedReason: 'PLAN_INCOMPLETE: planner reported a missing recipient or amount; nothing submitted'
    };
  }
  return { kind: 'submit', index: done, action };
}

module.exports = { nextAction };
