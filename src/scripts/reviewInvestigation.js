// Review CLI for persisted investigations.
//   node src/scripts/reviewInvestigation.js list [--limit N] [--verdict V] [--origin O] [--genuine-only]
//   node src/scripts/reviewInvestigation.js get <recordId>
//   node src/scripts/reviewInvestigation.js review <recordId>
//   node src/scripts/reviewInvestigation.js audit [--apply]   (B9 corpus quarantine; moves nothing without --apply)
const { listInvestigations, getInvestigation, quarantineInvestigations } = require('../services/investigationStore');
const { reviewInvestigation } = require('../services/reasoningRubric');

function main(argv) {
  const [cmd, ...rest] = argv;
  const fileFlag = (args) => {
    const i = args.indexOf('--file');
    return i >= 0 && args[i + 1] ? args[i + 1] : undefined;
  };
  if (cmd === 'list') {
    const opts = { limit: 20, file: fileFlag(rest) };
    for (let i = 0; i < rest.length; i += 1) {
      if (rest[i] === '--limit') opts.limit = parseInt(rest[i + 1], 10) || 20;
      if (rest[i] === '--verdict') opts.verdict = rest[i + 1];
      if (rest[i] === '--origin') opts.origin = rest[i + 1];
      if (rest[i] === '--genuine-only') opts.genuineOnly = true;
    }
    console.log(JSON.stringify(listInvestigations(opts), null, 1));
    return 0;
  }
  if (cmd === 'audit') {
    const apply = rest.includes('--apply');
    console.log(JSON.stringify(quarantineInvestigations({ file: fileFlag(rest), apply }), null, 1));
    return 0;
  }
  if (cmd === 'get' && rest[0]) {
    console.log(JSON.stringify(getInvestigation(rest[0], fileFlag(rest)), null, 1));
    return 0;
  }
  if (cmd === 'review' && rest[0]) {
    const found = getInvestigation(rest[0], fileFlag(rest));
    if (!found.ok) {
      console.log(JSON.stringify(found, null, 1));
      return 1;
    }
    console.log(JSON.stringify({ recordId: rest[0], rubric: reviewInvestigation(found.record) }, null, 1));
    return 0;
  }
  console.error('usage: reviewInvestigation.js list [--genuine-only]|get <id>|review <id>|audit [--apply]');
  return 2;
}

if (require.main === module) process.exit(main(process.argv.slice(2)));
module.exports = { main };
