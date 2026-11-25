import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { execute } from '../environment.mjs';
import { interopGroups } from './groups.mjs';
import { readInteropGroup } from './reports.mjs';

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

export function interopInvocation(group, consumer, directory) {
  if (group.runtime === 'bun') {
    const junit = path.join(directory, `${group.id}.junit.xml`);
    return {
      command: 'bun',
      args: [
        'test',
        '--preload',
        path.join(consumer, 'scripts/packed-consumer/preload-bun.mjs'),
        '--reporter=junit',
        `--reporter-outfile=${junit}`,
        ...group.targets,
      ],
      reports: { junit },
    };
  }
  const tap = path.join(directory, `${group.id}.tap.log`);
  const events = path.join(directory, `${group.id}.events.jsonl`);
  return {
    command: process.execPath,
    args: [
      `--import=${path.join(consumer, 'scripts/packed-consumer/preload-node.mjs')}`,
      '--test',
      '--test-reporter=tap',
      `--test-reporter-destination=${tap}`,
      `--test-reporter=${path.join(consumer, 'scripts/ci/interop/node-reporter.mjs')}`,
      `--test-reporter-destination=${events}`,
      ...group.targets,
    ],
    reports: { events, tap },
  };
}

export function runInteropGroups(consumer, bunPin, run = execute) {
  const directory = path.join(consumer, 'coverage/interop');
  mkdirSync(directory, { recursive: true });
  const bun = run('bun', ['--version'], consumer).trim();
  assert.equal(bun, bunPin, 'Bun differs from the SDK toolchain pin');
  assert.match(process.versions.node, /^24\./, 'Package Interop Node reporter requires Node 24');
  const groups = [];
  const cases = [];
  const files = [];
  for (const group of interopGroups) {
    const invocation = interopInvocation(group, consumer, directory);
    run(invocation.command, invocation.args, consumer, { stdio: 'inherit' });
    const report = readInteropGroup({ group, consumer, ...invocation.reports });
    cases.push(...report.cases);
    files.push(...report.files);
    groups.push({
      id: group.id,
      runtime: group.runtime,
      version: group.runtime === 'bun' ? bun : process.versions.node,
      files: [...report.files].sort(),
      leafCases: report.declaredTests,
      argv: invocation.args,
      cwd: consumer,
      exitCode: 0,
      reports: Object.fromEntries(
        Object.entries(invocation.reports).map(([type, file]) => [type, sha256(file)]),
      ),
    });
  }
  const loopArgs = [
    '--preload',
    path.join(consumer, 'scripts/packed-consumer/preload-bun.mjs'),
    'test/interop/run-internal-loop.mjs',
  ];
  run('bun', loopArgs, consumer, { stdio: 'inherit' });
  return {
    groups,
    internalLoop: { runtime: 'bun', version: bun, argv: loopArgs, cwd: consumer, exitCode: 0 },
    report: { files: files.sort(), cases, declaredTests: cases.length },
  };
}
