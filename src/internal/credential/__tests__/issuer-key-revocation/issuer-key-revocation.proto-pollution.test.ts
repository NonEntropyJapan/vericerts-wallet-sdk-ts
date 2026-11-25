/**
 * FC-11（鍵無効化宣言）の `issuerTrust` 読み取りの `Object.prototype` 汚染耐性。
 *
 * `assertSigningKeyNotRevoked` は呼び出し側が組み立てた `issuerTrust` の中身を読む。ここを
 * プロトタイプ鎖で読むと、**そのプロパティを省略した正当な検証**が汚染値を拾い、FC-11 が
 * 例外も警告も出さずに素通りする（fail-open）。FC-11 は fail-closed であり `failSafePolicy` に
 * よる緩和の対象外なので、素通りは仕様違反そのものになる。
 *
 * 本ファイルが固定するのは次の 2 つの汚染経路である。
 *
 * 1. `issuer` 汚染: `IssuerTrustOption.issuer` は「leaf 以外のエンティティが署名した VC を判定する
 *    場合のみ明示する」任意プロパティで、**省略するのが通常の使い方**。汚染値を拾うと突合対象の
 *    subject が攻撃者の選んだエンティティにすり替わり、その subject には宣言が無いため
 *    「宣言が無い以上、拒否し得る VC は存在しない」の早期 return に落ちて失効鍵の VC が受理される。
 * 2. `trustChain` 汚染: `trustChain` を own プロパティとして持たない器を渡された場合、汚染値の
 *    「宣言 0 件の成立チェーン」を採用して突合が空振りする。
 *
 * 任意オプションはオブジェクト自身が持つ値だけを読む。
 */

import { describe, test } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../errors.js';
import type { IssuerTrustOption } from '../../issuer-key-revocation.js';
import {
  AFTER_REVOKED_ISO,
  declaration,
  expectThrowCode,
  ISSUER_ID,
  issueJwtVc,
  OTHER_ISSUER_ID,
  trustChain,
  verifyJwtVc,
} from './issuer-key-revocation.fixtures.js';

describe('assertSigningKeyNotRevoked の issuerTrust 汚染耐性', () => {
  test('継承した issuer では突合対象の subject がすり替わらない', () => {
    // leaf（ISSUER_ID）の SIGNING_KID を無効化した chain。`issuer` は省略して渡す＝ leaf を対象とする。
    const issuerTrust: IssuerTrustOption = { trustChain: trustChain([declaration(ISSUER_ID)]) };
    const jwt = issueJwtVc(AFTER_REVOKED_ISO);

    // 汚染が無ければ 5012 で拒否される（前提の確認）。
    expectThrowCode(() => verifyJwtVc(jwt, issuerTrust), ErrorCodes.FEDERATION_KEY_REVOKED);

    // `Object.prototype.issuer` に宣言を持たない別エンティティを仕込む。鎖読みだと subject が
    // これにすり替わり、宣言なし → 早期 return で**無言で受理**されてしまう。
    withPollutedPrototype({ issuer: OTHER_ISSUER_ID }, () => {
      expectThrowCode(() => verifyJwtVc(jwt, issuerTrust), ErrorCodes.FEDERATION_KEY_REVOKED);
    });
  });

  test('継承した trustChain は採用せず 5010 で fail-closed に倒す', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO);
    // `trustChain` を own プロパティとして持たない器（型の無い JS からの呼び出しを想定）。
    const empty = {} as IssuerTrustOption;
    // 宣言 0 件の「成立している」chain を汚染値として仕込む。鎖読みだとこれを採用して素通りする。
    const polluted = trustChain([]);

    withPollutedPrototype({ trustChain: polluted }, () => {
      expectThrowCode(() => verifyJwtVc(jwt, empty), ErrorCodes.TRUST_CHAIN_INVALID);
    });
  });
});
