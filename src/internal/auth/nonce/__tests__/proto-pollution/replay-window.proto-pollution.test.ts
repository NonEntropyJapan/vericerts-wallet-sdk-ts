/**
 * `assertWithinReplayWindow` の `Object.prototype` 汚染耐性テスト。
 *
 * `opts.windowSeconds` をプロトタイプ鎖で読むと、窓を**指定していない**正当な呼び出しでも
 * 継承値（例 `Infinity`）が実効窓になり、KB-JWT / VP のリプレイ窓が丸ごと無効化される。
 * `opts.nowSeconds` も同様に、攻撃者が選んだ「現在時刻」で `iat` が評価される。
 *
 * あわせて `REPLAY_WINDOW_SECONDS_BY_FLOW` が `Object.create(null)` 由来であること
 * （型外の flow 名が `Object.prototype` に当たらないこと）も検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { assertWithinReplayWindow, REPLAY_WINDOW_SECONDS_BY_FLOW } from '../../replay-window.js';
import type { NonceFlow } from '../../types.js';

const NOW = 1_767_225_600;

describe('assertWithinReplayWindow の Object.prototype 汚染耐性', () => {
  it('継承した windowSeconds: Infinity はリプレイ窓を無効化しない', () => {
    // oid4vp の既定窓は 30 秒。10 万秒前の `iat` は必ず窓外。
    expect(() =>
      withPollutedPrototype({ windowSeconds: Number.POSITIVE_INFINITY }, () => {
        assertWithinReplayWindow(NOW - 100_000, 'oid4vp', { nowSeconds: NOW });
      }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('継承した nowSeconds は現在時刻の判定基準にならない', () => {
    // 汚染した `nowSeconds` を拾えば「窓内」に見えるが、拾わなければ実時刻との差で窓外になる。
    expect(() =>
      withPollutedPrototype({ nowSeconds: NOW }, () => {
        assertWithinReplayWindow(NOW, 'oid4vp', {});
      }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('未知 flow はリプレイ窓検査を素通りせず 4014 で拒否する（fail-closed）', () => {
    // `Object.create(null)` 化で既定窓が引けなくなるため `window` は undefined になる。
    // `Math.abs(...) > undefined` は NaN 比較で常に false なので、ガードが無いと
    // **窓検査が丸ごとスキップ**される（fail-open）。窓外の `iat` が拒否されることで確認する。
    expect(() => {
      assertWithinReplayWindow(NOW - 100_000, 'constructor' as NonceFlow, { nowSeconds: NOW });
    }).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
    // 窓内に見える `iat` でも、そもそも既定窓が決まらない以上は受理してはならない。
    expect(() => {
      assertWithinReplayWindow(NOW, 'toString' as NonceFlow, { nowSeconds: NOW });
    }).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('windowSeconds が非有限・負値なら 4014 で拒否する', () => {
    expect(() => {
      assertWithinReplayWindow(NOW, 'oid4vp', { nowSeconds: NOW, windowSeconds: Number.NaN });
    }).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
    expect(() => {
      assertWithinReplayWindow(NOW, 'oid4vp', { nowSeconds: NOW, windowSeconds: -1 });
    }).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('REPLAY_WINDOW_SECONDS_BY_FLOW は Object.prototype を辿らない', () => {
    expect(Object.getPrototypeOf(REPLAY_WINDOW_SECONDS_BY_FLOW)).toBeNull();
    // 型外の flow 名（JS からの呼び出し）が prototype のメンバに当たらないこと。
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW['constructor' as NonceFlow]).toBeUndefined();
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW['toString' as NonceFlow]).toBeUndefined();
  });

  it('明示的に渡した windowSeconds / nowSeconds は従来どおり効く（正常系）', () => {
    // 明示指定した広い窓なら受理される。
    expect(() => {
      assertWithinReplayWindow(NOW - 100_000, 'oid4vp', {
        nowSeconds: NOW,
        windowSeconds: 200_000,
      });
    }).not.toThrow();
    // 既定窓の内側も従来どおり受理される。
    expect(() => {
      assertWithinReplayWindow(NOW - 5, 'oid4vp', { nowSeconds: NOW });
    }).not.toThrow();
  });
});
