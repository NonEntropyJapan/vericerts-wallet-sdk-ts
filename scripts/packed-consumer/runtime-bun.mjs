import { installBunBoundary } from './boundary-bun.mjs';

const assertNoViolations = installBunBoundary();
await import('./runtime.mjs');
assertNoViolations();
