/**
 * 既定の検証経路の回帰テスト。
 *
 * 修正前は `opts.verifyReceived` の「既定検証を置換するかどうかの判定」
 * （`nonObjectPrototypeProperty(opts, 'verifyReceived')`）と「実際に検証関数を実行する経路」
 * （`{...opts}` によるスプレッド。own enumerable プロパティのみコピー）が別の読みに割れていた。
 * `verifyReceived` をプロトタイプメソッド（`own-property.ts` の規約どおりの正当な DI 形）や
 * 副作用のある getter で公開する `opts` を渡すと、判定は「カスタム検証あり」と誤認して既定検証を
 * スキップする一方、実行側には値が渡らずカスタム検証も呼ばれない ―― **署名検証が一切走らずに
 * VC が受理される**（fail-open）。
 *
 * OID4VCI フロー配線のテストは `wallet.receive-credential.test.ts`、既定署名検証の正常系・異常系は
 * `wallet.receive-credential.default-verify.test.ts` に分離している（Linterly の 300 行/ファイル
 * 上限）。共有フィクスチャは `receive-credential-fixtures.ts` にある。
 */

import { describe, expect, it } from 'bun:test';
import { preAuthorizedOfferURI } from '../../../internal/auth/oid4vci/facade/__tests__/facade-fixtures.js';
import { ErrorCodes } from '../../../internal/errors.js';
import type { FetchLike } from '../../../internal/fetch-di.js';
import {
  buildIssuedSdJwt,
  credentialStub,
  setupWallet,
  UNRESOLVABLE_ISSUER_DID,
} from './receive-credential-fixtures.js';

describe('Wallet.receiveCredential（opts.verifyReceived の読み取り一貫性）', () => {
  it('class ベースの verifyReceived（プロトタイプメソッド DI）は既定検証を正しく置換・実行する', async () => {
    // 修正前はここで検証ゼロのまま ACCEPTED していた（未対応 DID メソッドのため既定検証なら
    // issuer_key_unresolved になるはずの VC）。
    class VerifyReceivedOpts {
      readonly fetchImpl: FetchLike;
      calls = 0;
      constructor(fetchImpl: FetchLike) {
        this.fetchImpl = fetchImpl;
      }
      // プロトタイプメソッド。own enumerable プロパティではないため `{...opts}` ではコピーされない。
      verifyReceived(): void {
        this.calls += 1;
        throw new Error('custom verify rejects');
      }
    }
    const stub = credentialStub(buildIssuedSdJwt(UNRESOLVABLE_ISSUER_DID));
    const opts = new VerifyReceivedOpts(stub.fetchImpl);
    const wallet = await setupWallet();

    await expect(wallet.receiveCredential(preAuthorizedOfferURI(), opts)).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'received_credential_signature_invalid' },
    });
    // カスタム検証が実際に呼ばれたこと（修正前は呼ばれずに ACCEPTED していた）。
    expect(opts.calls).toBe(1);
  });

  it('副作用のある getter（呼ぶたびに違う値を返す）で verifyReceived を公開しても検証ゼロで受理されない', async () => {
    // 1 回目は undefined、2 回目以降は必ず throw する関数を返す getter。修正前は「実行用の読み
    // （スプレッド。1 回目）」が undefined を、「判定用の読み（hasCustomVerify。2 回目）」が
    // 関数を拾う食い違いにより、既定検証がスキップされたままカスタム検証も呼ばれず受理されていた。
    let reads = 0;
    const stub = credentialStub(buildIssuedSdJwt(UNRESOLVABLE_ISSUER_DID));
    const opts = {
      fetchImpl: stub.fetchImpl,
      get verifyReceived(): ((raw: string) => void) | undefined {
        reads += 1;
        return reads === 1
          ? undefined
          : () => {
              throw new Error('custom verify rejects');
            };
      },
    };
    const wallet = await setupWallet();

    // 修正後は「判定」と「実行」が同じ 1 回の読みに揃うため、既定検証への fall-through
    // （issuer_key_unresolved）かカスタム検証の実行（received_credential_signature_invalid）の
    // いずれかで必ず 3010 になり、検証ゼロで ACCEPTED になることはない。
    await expect(wallet.receiveCredential(preAuthorizedOfferURI(), opts)).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
    });
    expect(reads).toBeGreaterThan(0);
  });
});
