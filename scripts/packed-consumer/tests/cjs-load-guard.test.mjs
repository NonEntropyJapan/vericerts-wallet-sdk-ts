import { expect, test } from 'bun:test';
import assert from 'node:assert/strict';
import { join, resolve } from 'node:path';
import {
  assertCjsFile,
  checkCjsStartupCache,
  closeBootstrapPorts,
  createCjsViolationRecorder,
  installCjsLoadGuard,
} from '../cjs-load-guard.mjs';
import { inside } from '../containment.mjs';

const root = resolve('/virtual-consumer');
const own = join(root, 'entry.cjs');
const alias = join(root, 'alias.cjs');
const sibling = `${root}-other/entry.cjs`;
const linked = join(root, 'linked.cjs');

function fakePolicy(base, filename) {
  const realpath = new Map([
    [own, own],
    [alias, own],
    [sibling, sibling],
    [linked, sibling],
  ]).get(filename);
  assert.ok(realpath, 'Missing mock module');
  assert.ok(inside(base, realpath), 'Mock module escapes consumer');
  return realpath;
}

test('validates the realpath but delegates once with the original file, receiver and arguments', () => {
  const events = [];
  const result = {};
  const prototype = {
    load(...args) {
      events.push(['load', this, ...args]);
      return result;
    },
  };
  const descriptor = Object.getOwnPropertyDescriptor(prototype, 'load');
  const violations = createCjsViolationRecorder(() => assert.fail('Unexpected exit failure'));
  const restore = installCjsLoadGuard(prototype, root, violations.record, (base, filename) => {
    events.push(['check', base, filename]);
    return fakePolicy(base, filename);
  });
  try {
    const receiver = Object.create(prototype);
    const option = {};
    expect(receiver.load(alias, option, undefined)).toBe(result);
    expect(events).toEqual([
      ['check', root, alias],
      ['load', receiver, alias, option, undefined],
    ]);
    expect(events[1][1]).toBe(receiver);
    expect(events[1][3]).toBe(option);
    expect(violations.count).toBe(0);
    expect(Object.getOwnPropertyDescriptor(prototype, 'load')).toEqual({
      ...descriptor,
      value: receiver.load,
    });
  } finally {
    restore();
  }
  expect(Object.getOwnPropertyDescriptor(prototype, 'load')).toEqual(descriptor);
});

test('denials never enter the mock loader or read contents and record a shared sticky failure', () => {
  let loaderCalls = 0;
  let contentReads = 0;
  let checks = 0;
  const readContents = () => contentReads++;
  const prototype = {
    load() {
      loaderCalls++;
      readContents();
    },
  };
  const checkFile = (base, filename) => {
    checks++;
    return fakePolicy(base, filename);
  };
  const marks = [];
  const violations = createCjsViolationRecorder(() => marks.push(violations.count));
  const restore = installCjsLoadGuard(prototype, root, violations.record, checkFile);
  try {
    for (const filename of [undefined, '', 'relative.cjs']) {
      expect(() => prototype.load(filename)).toThrow('Expected an absolute');
    }
    expect(checks).toBe(0);
    for (const filename of [sibling, linked]) {
      expect(() => prototype.load(filename)).toThrow('Mock module escapes consumer');
    }
    expect(() => prototype.load(join(root, 'missing.cjs'))).toThrow('Missing mock module');
    expect(() => assertCjsFile(root, sibling, violations.record, checkFile)).toThrow(
      'Mock module escapes consumer',
    );
    expect(checks).toBe(4);
    expect(loaderCalls).toBe(0);
    expect(contentReads).toBe(0);
    expect(marks).toEqual([1, 2, 3, 4, 5, 6, 7]);
    prototype.load(own);
    expect(loaderCalls).toBe(1);
    expect(contentReads).toBe(1);
    expect(violations.count).toBe(7);
  } finally {
    restore();
  }
});

test('keeps the denial and sticky count if marking the exit status throws', () => {
  const denied = new Error('Denied by mock file policy');
  const violations = createCjsViolationRecorder(() => {
    throw new Error('Cannot mark exit');
  });
  const checkFile = () => {
    throw denied;
  };
  assert.throws(
    () => assertCjsFile(root, own, violations.record, checkFile),
    (error) => error === denied,
  );
  expect(violations.count).toBe(1);
});

test('propagates the original loader error without recording a violation', () => {
  const failure = new Error('Original loader failed');
  let calls = 0;
  const prototype = {
    load() {
      calls++;
      throw failure;
    },
  };
  const violations = createCjsViolationRecorder(() => assert.fail('Unexpected exit failure'));
  const restore = installCjsLoadGuard(prototype, root, violations.record, fakePolicy);
  try {
    assert.throws(
      () => prototype.load(own),
      (error) => error === failure,
    );
    expect(calls).toBe(1);
    expect(violations.count).toBe(0);
  } finally {
    restore();
  }
});

test('validates all own startup cache keys without invoking accessor entries', () => {
  const cache = Object.create(null);
  expect(() => checkCjsStartupCache(root, cache, fakePolicy)).not.toThrow();
  Object.defineProperty(cache, own, { value: {} });
  cache[alias] = {};
  const visited = [];
  checkCjsStartupCache(root, cache, (base, filename) => {
    visited.push(filename);
    return fakePolicy(base, filename);
  });
  expect(visited).toEqual([own, alias]);
  cache[linked] = {};
  expect(() => checkCjsStartupCache(root, cache, fakePolicy)).toThrow('Mock module escapes');
  delete cache[linked];
  cache[Symbol('cache key')] = {};
  expect(() => checkCjsStartupCache(root, cache, fakePolicy)).toThrow('Expected an absolute');
  let reads = 0;
  const accessor = Object.defineProperty(Object.create(null), own, {
    get() {
      reads++;
      return {};
    },
  });
  expect(() => checkCjsStartupCache(root, accessor, fakePolicy)).toThrow('Unexpected CommonJS');
  expect(reads).toBe(0);
  for (const malformed of [null, {}, []]) {
    expect(() => checkCjsStartupCache(root, malformed, fakePolicy)).toThrow('startup cache');
  }
});

test('fails setup for absent, accessor or immutable load definitions without changing them', () => {
  let reads = 0;
  const invalid = [
    {},
    Object.defineProperty({}, 'load', {
      get() {
        reads++;
        return () => {};
      },
    }),
    Object.defineProperty({}, 'load', { value: () => {} }),
  ];
  for (const prototype of invalid) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, 'load');
    expect(() => installCjsLoadGuard(prototype, root, () => {}, fakePolicy)).toThrow(
      'Cannot guard CommonJS module loads',
    );
    expect(Object.getOwnPropertyDescriptor(prototype, 'load')).toEqual(descriptor);
  }
  expect(reads).toBe(0);
});

test('attempts cleanup of every supplied port even if a close fails', () => {
  const closed = [];
  closeBootstrapPorts(
    {
      close() {
        closed.push(1);
        throw new Error('Mock close failed');
      },
    },
    { close: () => closed.push(2) },
  );
  expect(closed).toEqual([1, 2]);
});
