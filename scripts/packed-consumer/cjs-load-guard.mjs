import assert from 'node:assert/strict';
import { isAbsolute } from 'node:path';
import { containedFile } from './containment.mjs';

function checkCjsFile(root, filename, checkFile) {
  assert.ok(
    typeof filename === 'string' && isAbsolute(filename),
    'Expected an absolute CommonJS module filename',
  );
  checkFile(root, filename);
}

export function assertCjsFile(root, filename, recordViolation, checkFile = containedFile) {
  try {
    checkCjsFile(root, filename, checkFile);
  } catch (error) {
    recordViolation();
    throw error;
  }
}

export function createCjsViolationRecorder(markExitFailed) {
  let count = 0;
  return {
    get count() {
      return count;
    },
    record() {
      count++;
      try {
        markExitFailed();
      } catch {
        // Preserve the violation for the exit check and let the boundary error propagate.
      }
    },
  };
}

export function checkCjsStartupCache(root, cache, checkFile = containedFile) {
  assert.ok(
    cache && typeof cache === 'object' && Object.getPrototypeOf(cache) === null,
    'Unexpected CommonJS startup cache',
  );
  for (const filename of Reflect.ownKeys(cache)) {
    checkCjsFile(root, filename, checkFile);
    const entry = Object.getOwnPropertyDescriptor(cache, filename)?.value;
    assert.ok(entry && typeof entry === 'object', 'Unexpected CommonJS startup cache entry');
  }
}

export function installCjsLoadGuard(prototype, root, recordViolation, checkFile = containedFile) {
  const original = Object.getOwnPropertyDescriptor(prototype, 'load');
  assert.ok(
    typeof original?.value === 'function' && (original.writable || original.configurable),
    'Cannot guard CommonJS module loads',
  );
  function guardedLoad(...args) {
    assertCjsFile(root, args[0], recordViolation, checkFile);
    return Reflect.apply(original.value, this, args);
  }
  Object.defineProperty(prototype, 'load', { ...original, value: guardedLoad });
  return () => Object.defineProperty(prototype, 'load', original);
}

export function closeBootstrapPorts(...ports) {
  for (const port of ports) {
    try {
      port.close();
    } catch {
      // Keep the bootstrap error and attempt cleanup of the remaining port.
    }
  }
}
