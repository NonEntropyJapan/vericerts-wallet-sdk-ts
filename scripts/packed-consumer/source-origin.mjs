import assert from 'node:assert/strict';

export const COMMITTED_PROJECTION = 'committed-projection';
export const DEVELOPMENT_SNAPSHOT = 'development-snapshot';

export function requireValidationOrigin(origin) {
  assert.ok(
    origin === COMMITTED_PROJECTION || origin === DEVELOPMENT_SNAPSHOT,
    'Explicit SDK validation origin is required',
  );
  return origin;
}
