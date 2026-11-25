export const DISABLING = new Set([
  'skip',
  'skipIf',
  'todo',
  'fixme',
  'only',
  'fail',
  'fails',
  'failing',
  'runIf',
  'if',
]);
export const UNAMBIGUOUS = new Set(['skip', 'skipIf', 'todo', 'fixme', 'only', 'runIf']);
export const RUNTIME_SKIPS = new Set(['skip', 'todo', 'fixme', 'fail']);
