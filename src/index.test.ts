import { describe, expect, test } from 'bun:test';
import { SDK_VERSION } from './index';

describe('SDK entrypoint', () => {
  test('exports a non-empty semver version', () => {
    expect(SDK_VERSION).toBeDefined();
    expect(SDK_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
