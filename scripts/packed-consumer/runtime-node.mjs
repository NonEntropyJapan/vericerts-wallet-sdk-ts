import { installNodeBoundary } from './boundary-node.mjs';

const runWithBoundary = installNodeBoundary();
await runWithBoundary(() => import('./runtime.mjs'));
