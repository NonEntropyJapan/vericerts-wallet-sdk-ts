/**
 * 応答本文の解放漏れの回帰テスト。
 *
 * 背景:
 * `http/body-limit.ts` に {@link discardBody} を置き、「取得経路の `finally` から
 * 呼ぶ」ことを docblock で規定した。しかし規約が docblock にしか無かったため、同じスイープ内の
 * 後続コミットがそれを採らず、`federation/entity-configuration.ts` と `federation/subordinate.ts`
 * という双子の取得経路で片方だけが本文を解放する状態になった（同形の取りこぼしが他 14 経路）。
 *
 * 未消費の応答本文は undici でもブラウザでも接続とバッファ済みバイトを GC まで保持する。
 * 非 2xx / Content-Type 不正 / 宣言サイズ超過で**本文を読む前に throw する**経路は、放っておくと
 * ソケットを掴んだまま残る。攻撃者が支配する取得先（`request_uri` は QR 由来、`entity_id` は
 * Federation の外部入力）へ繰り返し踏ませられる経路ほど効く。
 *
 * 規約が「どの Issue がそのファイルを名指ししたか」に依存し続けないよう、機械的に固定する。
 * biome も linterly も「取得した `Response` を解放しているか」は見ないため、検査はここだけで行う。
 *
 * 検証内容:
 * 製品コードで `Response` を受け取るローカル変数を宣言するモジュール（＝ fetch の戻り値を自分で
 * 保持し、その寿命に責任を持つモジュール）は、`discardBody` を呼んでいる。
 *
 * 本検査は「呼んでいること」までしか見ない（`finally` に在るか、全経路を覆うかは見ない）。
 * それでも、新しい取得経路が解放をまるごと忘れる——実際に起きた失敗の形——は確実に落ちる。
 */

import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { collectSources, isTestSupport, SRC_ROOT } from './layer-map.js';

/**
 * `Response` を保持するローカル変数の宣言（例: `let response: Response | undefined;`）。
 *
 * 引数やヘルパーの仮引数（`function f(response: Response)`）は対象外にする。後者は `Response` を
 * 受け取るだけで寿命を持たず、解放は渡した側の責務だから（`oid4vci-credential-response.ts` /
 * `http/body-limit.ts` の各ヘルパーが該当する）。
 */
const RESPONSE_HOLDER = /^\s*(?:let|const|var)\s+\w+\s*:\s*Response\b/m;

/** `discardBody` の呼び出し。 */
const DISCARD_CALL = /\bdiscardBody\s*\(/;

/** {@link discardBody} の定義元。自分自身を「呼んでいない」と数えない。 */
const DEFINITION = join('internal', 'http', 'body-limit.ts');

const productionSources = collectSources(SRC_ROOT).filter((path) => !isTestSupport(path));

describe('取得した応答本文は読まないなら解放する', () => {
  it('走査対象のソースが空振りしていない', () => {
    // 「違反 0 件」が「1 ファイルも読んでいない」で緑になるのを防ぐ。
    expect(productionSources.length).toBeGreaterThanOrEqual(300);
  });

  it('Response を保持する製品モジュールを見落としていない', () => {
    // 正規表現がリファクタで空振りしたら、違反 0 件も意味を失う。既知の取得経路数を下限に置く。
    const holders = productionSources.filter((relPath) =>
      RESPONSE_HOLDER.test(readFileSync(join(SRC_ROOT, relPath), 'utf8')),
    );

    expect(holders.length).toBeGreaterThanOrEqual(20);
  });

  it('Response を保持する製品モジュールはすべて discardBody を呼ぶ', () => {
    const violations = productionSources.filter((relPath) => {
      if (relPath === DEFINITION) return false;
      const source = readFileSync(join(SRC_ROOT, relPath), 'utf8');
      return RESPONSE_HOLDER.test(source) && !DISCARD_CALL.test(source);
    });

    expect(violations).toEqual([]);
  });
});
