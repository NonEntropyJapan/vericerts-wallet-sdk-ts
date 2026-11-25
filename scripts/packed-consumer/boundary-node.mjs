import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import Module, { createRequire, isBuiltin, register } from 'node:module';
import { MessageChannel } from 'node:worker_threads';
import {
  assertCjsFile,
  checkCjsStartupCache,
  closeBootstrapPorts,
  createCjsViolationRecorder,
  installCjsLoadGuard,
} from './cjs-load-guard.mjs';

export function installNodeBoundary(consumer = process.cwd()) {
  const root = realpathSync(consumer);
  const failCjsExit = () => {
    if (!process.exitCode) process.exitCode = 1;
  };
  const cjsViolations = createCjsViolationRecorder(failCjsExit);
  checkCjsStartupCache(root, createRequire(import.meta.url).cache);
  // Keep the installed guards for the lifetime of this dedicated child process.
  installCjsLoadGuard(Module.prototype, root, cjsViolations.record);
  const originalRequire = Module.prototype.require;
  Module.prototype.require = function requireInsideConsumer(specifier) {
    const resolved = createRequire(this.filename).resolve(specifier);
    if (!isBuiltin(resolved)) assertCjsFile(root, resolved, cjsViolations.record);
    return originalRequire.call(this, specifier);
  };
  process.once('exit', () => {
    if (cjsViolations.count) failCjsExit();
  });

  const { port1, port2 } = new MessageChannel();
  let esmViolations = 0;
  const flushes = [];
  const flush = () =>
    new Promise((resolve) => {
      flushes.push(resolve);
      port1.postMessage('flush');
    });
  try {
    port1.on('message', (message) => {
      if (message === 'violation') esmViolations++;
      if (message === 'flushed') flushes.shift()?.();
    });
    register('./module-hooks.mjs', {
      parentURL: import.meta.url,
      data: { root, port: port2 },
      transferList: [port2],
    });
  } catch (error) {
    closeBootstrapPorts(port1, port2);
    throw error;
  }

  function beforeExit() {
    port1.ref();
    flush().then(() => {
      if (esmViolations) process.exitCode = 1;
      port1.close();
    });
  }

  // Preload-only use must allow the child to reach beforeExit without an entry assertion.
  port1.unref();
  process.once('beforeExit', beforeExit);
  return async (run) => {
    port1.ref();
    try {
      await run();
      await flush();
      assert.equal(
        esmViolations + cjsViolations.count,
        0,
        'Module attempted to leave isolated consumer',
      );
    } catch (error) {
      process.off('beforeExit', beforeExit);
      closeBootstrapPorts(port1);
      throw error;
    }
    port1.unref();
  };
}
