/**
 * TS SDK の実際の実装を使って言語非依存のコンフォーマンステストベクタを生成する CLI。
 *
 * 出力: SDK ルートの schemas/conformance-vectors.json。
 * Go 実装との互換性テストでも、同じ input と expected の組を使って結果を照合する。
 *
 * ケース定義は conformance/ 以下にカテゴリごとに分割する（Linterly 300行上限対応。
 * ecdsa/p256-signer.ts・ecdsa/secp256k1-signer.ts の分割方針に合わせる）。
 * 本ファイルはそれらを集約して JSON に書き出す薄い CLI エントリに徹する。
 *
 * 記法・fail-closed 方針は gen-error-codes.mjs に合わせる。
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import pkg from '../package.json' with { type: 'json' };
import { getDelegatedVcCases } from './conformance/delegated-vc-vectors.js';
import { getDidResolveCases } from './conformance/did-vectors.js';
import { getJwtVcCases } from './conformance/jwt-vc-vectors.js';
import { getSdJwtCases } from './conformance/sd-jwt-vectors.js';

const schemasDirUrl = new URL('../schemas/', import.meta.url);
const outUrl = new URL('../schemas/conformance-vectors.json', import.meta.url);

const cases = [
  ...getDidResolveCases(),
  ...getJwtVcCases(),
  ...getSdJwtCases(),
  ...(await getDelegatedVcCases()),
];

const generated = `${JSON.stringify({ generatedFrom: `${pkg.name}@${pkg.version}`, cases }, null, 2)}\n`;

if (process.argv.includes('--check')) {
  const current = (() => {
    try {
      return readFileSync(outUrl, 'utf8');
    } catch {
      return null;
    }
  })();
  if (current !== generated) {
    console.error(
      'conformance-vectors: schemas/conformance-vectors.json is stale. Run `bun run gen:conformance-vectors` and commit.',
    );
    process.exit(1);
  }
  console.log(`conformance-vectors: drift なし（${cases.length} 件）`);
  process.exit(0);
}

mkdirSync(schemasDirUrl, { recursive: true });
writeFileSync(outUrl, generated);
console.log(
  `conformance-vectors: schemas/conformance-vectors.json を生成しました（${cases.length} 件）`,
);
