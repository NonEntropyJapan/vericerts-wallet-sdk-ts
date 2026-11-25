#!/usr/bin/env node
// test/interop/wait-peers-healthy.mjs
//
// Compose のピアがマトリクスの実行前に起動したことを確認する。
// `docker compose ps -a --format json` の出力を標準入力から読み、全 peer が running かつ
// healthy なら exit 0、それ以外は不健全な peer を stderr に列挙して exit 1 にする。
//
// `-a` が必須: 既定の `docker compose ps` は実行中コンテナしか列挙しないため、起動直後に
// クラッシュ/停止した peer が一覧から消え、「不健全 0 件 = 全 peer healthy」と誤判定していた。
// 一覧が空（コンテナが 1 つも無い）、healthcheck を持たない peer（Health 空）も不健全として扱う。

import { readFileSync } from 'node:fs';
import { isMainModule } from '../../scripts/lib/is-main-module.mjs';

/**
 * 外部前提（`EBSI_SANDBOX_BASE_URL` 等）が無いと起動できず healthcheck も持たない peer。
 * run-peer-matrix.mjs が「prerequisite 未充足」としてスキップする対象なので待機対象から外す。
 */
export const OPTIONAL_PEERS = new Set(['ebsi-proxy']);

/** `docker compose ps --format json` の出力（NDJSON または JSON 配列）をサービス配列にする。 */
export function parsePsOutput(text) {
  const trimmed = text.trim();
  if (trimmed === '') return [];
  if (trimmed.startsWith('[')) return JSON.parse(trimmed);
  return trimmed
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

/** 不健全な peer の説明文の配列を返す（空配列 = 全 peer が running かつ healthy）。 */
export function findUnhealthyPeers(services, optional = OPTIONAL_PEERS) {
  const required = services.filter((s) => !optional.has(s.Service));
  if (required.length === 0) return ['no peer containers found'];
  return required
    .filter((s) => s.State !== 'running' || s.Health !== 'healthy')
    .map((s) => `${s.Service}: state=${s.State || '?'} health=${s.Health || '(none)'}`);
}

if (isMainModule(import.meta.url)) {
  const unhealthy = findUnhealthyPeers(parsePsOutput(readFileSync(0, 'utf8')));
  if (unhealthy.length > 0) {
    console.error(`unhealthy peers:\n${unhealthy.join('\n')}`);
    process.exit(1);
  }
}
