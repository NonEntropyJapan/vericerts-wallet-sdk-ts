/**
 * DID Document 差分適用（`applyDidDocumentUpdate`）の単体テスト。
 *
 * 検証する規則:
 * - 削除 → 追加の順で適用する（同一 id の入れ替えが 1 回の呼び出しで表現できる）。
 * - 存在しないものの削除・既にある id の追加はいずれも `2010` で拒否する。
 * - VerificationMethod を削除すると全 relationship 配列から参照も外れる（埋め込み形式も）。
 *   ただし同一呼び出しで同じ id を再追加する鍵ローテーションでは参照（文字列）だけ残る。
 * - 追加は `verificationMethod` にだけ載り、relationship は変わらない。
 * - controller は文字列・配列のどちらの表現でも扱え、空になればキーごと落ちる。
 * - 差分が 1 つも無い呼び出しは `2010`（`empty_update`）。
 * - 入力の Document を破壊しない。
 * - `Object.prototype` 汚染を差分として拾わない（データ汚染・アクセサ汚染の両方）。
 * - `deepSnapshot` で確定値へ畳めない値（クラスインスタンス等）の追加は拒否する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, Service, VerificationMethod } from '../did.js';
import { applyDidDocumentUpdate } from '../did-document-patch.js';

const DID = 'did:stub:subject';

/** 既存の VerificationMethod（relationship からも参照される）。 */
const EXISTING_METHOD: VerificationMethod = {
  id: `${DID}#key-1`,
  type: 'Multikey',
  controller: DID,
  publicKeyMultibase: 'zExisting',
};

/** 追加用の VerificationMethod。 */
const NEW_METHOD: VerificationMethod = {
  id: `${DID}#key-2`,
  type: 'Multikey',
  controller: DID,
  publicKeyMultibase: 'zNew',
};

/** 追加用の Service。 */
const NEW_SERVICE: Service = {
  id: `${DID}#dwn`,
  type: 'DIDCommMessaging',
  serviceEndpoint: 'https://example.test/dwn',
};

/** 参照・埋め込みの両形式で `#key-1` を持つ DID Document。 */
function baseDocument(): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: DID,
    verificationMethod: [EXISTING_METHOD],
    authentication: [`${DID}#key-1`],
    // 埋め込み形式（参照ではなく VerificationMethod そのもの）も同じ id で外れること。
    assertionMethod: [EXISTING_METHOD],
    capabilityInvocation: [`${DID}#key-1`],
  };
}

/** 投げられた VericertsError の `code` と `context.reason` を取り出す。 */
function failureOf(run: () => unknown): { code: string; reason: unknown } {
  try {
    run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    const error = e as VericertsError;
    return { code: error.code, reason: error.context?.reason };
  }
  throw new Error('should throw');
}

describe('applyDidDocumentUpdate: 追加', () => {
  it('addVerificationMethod は verificationMethod にだけ載り relationship は変わらない', () => {
    const next = applyDidDocumentUpdate(baseDocument(), { addVerificationMethod: NEW_METHOD });
    expect(next.verificationMethod.map((method) => method.id)).toEqual([
      `${DID}#key-1`,
      `${DID}#key-2`,
    ]);
    // どの relationship に紐づけるかは UpdateDIDOptions が表現していないため推測しない。
    expect(next.authentication).toEqual([`${DID}#key-1`]);
    expect(next.capabilityInvocation).toEqual([`${DID}#key-1`]);
  });

  it('addService は service が無い Document にも載る', () => {
    const next = applyDidDocumentUpdate(baseDocument(), { addService: NEW_SERVICE });
    expect(next.service).toEqual([NEW_SERVICE]);
  });

  it('addController は controller が無い Document に配列として載る', () => {
    const next = applyDidDocumentUpdate(baseDocument(), { addController: 'did:stub:controller' });
    expect(next.controller).toEqual(['did:stub:controller']);
  });

  it('addController は文字列表現の controller にも追記できる', () => {
    const document = { ...baseDocument(), controller: 'did:stub:first' };
    const next = applyDidDocumentUpdate(document, { addController: 'did:stub:second' });
    expect(next.controller).toEqual(['did:stub:first', 'did:stub:second']);
  });

  it('既にある id の追加は 2010(verification_method_exists)', () => {
    expect(
      failureOf(() =>
        applyDidDocumentUpdate(baseDocument(), { addVerificationMethod: EXISTING_METHOD }),
      ),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'verification_method_exists' });
  });

  it('id を欠く VerificationMethod の追加は 2010(verification_method_id_missing)', () => {
    const malformed = { type: 'Multikey', controller: DID } as unknown as VerificationMethod;
    expect(
      failureOf(() => applyDidDocumentUpdate(baseDocument(), { addVerificationMethod: malformed })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'verification_method_id_missing' });
  });
});

describe('applyDidDocumentUpdate: 削除', () => {
  it('removeVerificationMethod は参照形式・埋め込み形式のどちらの relationship 参照も外す', () => {
    const next = applyDidDocumentUpdate(baseDocument(), {
      removeVerificationMethod: `${DID}#key-1`,
    });
    expect(next.verificationMethod).toEqual([]);
    // 解決不能な参照が残った不正な Document にしない。
    expect(next.authentication).toEqual([]);
    expect(next.assertionMethod).toEqual([]);
    expect(next.capabilityInvocation).toEqual([]);
  });

  it('removeService は最後の 1 件を消すとキーごと落とす', () => {
    const document = { ...baseDocument(), service: [NEW_SERVICE] };
    const next = applyDidDocumentUpdate(document, { removeService: NEW_SERVICE.id });
    expect(Object.hasOwn(next, 'service')).toBe(false);
  });

  it('removeController は最後の 1 件を消すとキーごと落とす', () => {
    const document = { ...baseDocument(), controller: ['did:stub:controller'] };
    const next = applyDidDocumentUpdate(document, { removeController: 'did:stub:controller' });
    expect(Object.hasOwn(next, 'controller')).toBe(false);
  });

  it('存在しない VerificationMethod の削除は 2010(verification_method_not_found)', () => {
    // 「削除したつもり」を成功にすると、失効させたはずの鍵で署名が通り続ける。
    expect(
      failureOf(() =>
        applyDidDocumentUpdate(baseDocument(), { removeVerificationMethod: `${DID}#absent` }),
      ),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'verification_method_not_found' });
  });

  it('存在しない Service の削除は 2010(service_not_found)', () => {
    expect(
      failureOf(() => applyDidDocumentUpdate(baseDocument(), { removeService: `${DID}#absent` })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'service_not_found' });
  });

  it('存在しない controller の削除は 2010(controller_not_found)', () => {
    expect(
      failureOf(() =>
        applyDidDocumentUpdate(baseDocument(), { removeController: 'did:stub:none' }),
      ),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'controller_not_found' });
  });
});

describe('applyDidDocumentUpdate: 適用順序と不変性', () => {
  it('削除 → 追加の順なので同一 id の入れ替えが 1 回で表現できる', () => {
    const rotated: VerificationMethod = { ...EXISTING_METHOD, publicKeyMultibase: 'zRotated' };
    const next = applyDidDocumentUpdate(baseDocument(), {
      removeVerificationMethod: EXISTING_METHOD.id,
      addVerificationMethod: rotated,
    });
    expect(next.verificationMethod).toEqual([rotated]);
    // 参照が外れたままだと authentication / assertionMethod が空になり、回転した新しい鍵で
    // どの用途の認証も通らない DID Document ができてしまう。
    expect(next.authentication).toEqual([`${DID}#key-1`]);
    expect(next.capabilityInvocation).toEqual([`${DID}#key-1`]);
    // 埋め込み形式は古い鍵素材そのものなので残さない（残すと失効させた鍵が生き続ける）。
    expect(next.assertionMethod).toEqual([]);
  });

  it('別 id を追加する削除では relationship 参照を残さない', () => {
    const next = applyDidDocumentUpdate(baseDocument(), {
      removeVerificationMethod: EXISTING_METHOD.id,
      addVerificationMethod: NEW_METHOD,
    });
    expect(next.verificationMethod).toEqual([NEW_METHOD]);
    expect(next.authentication).toEqual([]);
    expect(next.capabilityInvocation).toEqual([]);
  });

  it('入力の Document を破壊しない', () => {
    const document = baseDocument();
    applyDidDocumentUpdate(document, { addVerificationMethod: NEW_METHOD });
    expect(document.verificationMethod).toEqual([EXISTING_METHOD]);
  });

  it('差分が 1 つも無い呼び出しは 2010(empty_update)', () => {
    expect(failureOf(() => applyDidDocumentUpdate(baseDocument(), {}))).toEqual({
      code: ErrorCodes.DID_DOC_INVALID,
      reason: 'empty_update',
    });
  });
});

describe('applyDidDocumentUpdate: プロトタイプ汚染耐性', () => {
  it('Object.prototype.addController の汚染を差分として拾わない', () => {
    // 拾うと、差分を指定していない呼び出しで攻撃者の DID が controller に載る（DID 乗っ取り）。
    const next = withPollutedPrototype({ addController: 'did:stub:attacker' }, () =>
      applyDidDocumentUpdate(baseDocument(), { addService: NEW_SERVICE }),
    );
    expect(Object.hasOwn(next, 'controller')).toBe(false);
  });

  it('Object.prototype.removeVerificationMethod の汚染を差分として拾わない', () => {
    // 拾うと、毎回の更新で正規の鍵が黙って落ちる。
    const next = withPollutedPrototype({ removeVerificationMethod: `${DID}#key-1` }, () =>
      applyDidDocumentUpdate(baseDocument(), { addService: NEW_SERVICE }),
    );
    expect(next.verificationMethod).toEqual([EXISTING_METHOD]);
  });

  it('アクセサ形式の汚染も差分として拾わない', () => {
    // getter は読まれるたびに新しい値を返せるので、汚染値との同一性比較では塞げない。
    const next = withPollutedPrototypeAccessor(
      {
        addController: () => 'did:stub:attacker',
        addVerificationMethod: () => ({ ...NEW_METHOD }),
      },
      () => applyDidDocumentUpdate(baseDocument(), { addService: NEW_SERVICE }),
    );
    expect(Object.hasOwn(next, 'controller')).toBe(false);
    expect(next.verificationMethod).toEqual([EXISTING_METHOD]);
  });

  it('汚染だけで差分が無い呼び出しは empty_update のまま', () => {
    expect(
      failureOf(() =>
        withPollutedPrototype({ addController: 'did:stub:attacker' }, () =>
          applyDidDocumentUpdate(baseDocument(), {}),
        ),
      ),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'empty_update' });
  });
});

describe('applyDidDocumentUpdate: 追加する構造体の検査', () => {
  it('確定値へ畳めない VerificationMethod（クラスインスタンス）は 2010 で拒否する', () => {
    // `deepSnapshot` はプレーンなコンテナしか畳まない。畳めていない値は own アクセサが生き残り、
    // Art.9 ガードが見た値と公開される Document を食い違わせられる。
    class Method {
      readonly id = `${DID}#key-2`;
      readonly type = 'Multikey';
      readonly controller = DID;
    }
    expect(
      failureOf(() =>
        applyDidDocumentUpdate(baseDocument(), {
          addVerificationMethod: new Method() as unknown as VerificationMethod,
        }),
      ),
    ).toEqual({
      code: ErrorCodes.DID_DOC_INVALID,
      reason: 'verification_method_not_foldable',
    });
  });

  it('`getPrototypeOf` トラップ付き Proxy の Service も 2010 で拒否する', () => {
    const proxied = new Proxy({ ...NEW_SERVICE }, { getPrototypeOf: () => Date.prototype });
    expect(
      failureOf(() => applyDidDocumentUpdate(baseDocument(), { addService: proxied })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'service_not_foldable' });
  });

  it('type / controller を欠く VerificationMethod は 2010(verification_method_invalid)', () => {
    const malformed = { id: `${DID}#key-2` } as unknown as VerificationMethod;
    expect(
      failureOf(() => applyDidDocumentUpdate(baseDocument(), { addVerificationMethod: malformed })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'verification_method_invalid' });
  });

  it('serviceEndpoint を欠く Service は 2010(service_invalid)', () => {
    const malformed = { id: `${DID}#dwn`, type: 'DIDCommMessaging' } as unknown as Service;
    expect(
      failureOf(() => applyDidDocumentUpdate(baseDocument(), { addService: malformed })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'service_invalid' });
  });

  it('id を欠く Service の追加は 2010(service_id_missing)', () => {
    const malformed = { type: 'DIDCommMessaging', serviceEndpoint: 'https://x.test' };
    expect(
      failureOf(() =>
        applyDidDocumentUpdate(baseDocument(), { addService: malformed as unknown as Service }),
      ),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'service_id_missing' });
  });

  it('既にある id の Service 追加は 2010(service_exists)', () => {
    const document = { ...baseDocument(), service: [NEW_SERVICE] };
    expect(
      failureOf(() => applyDidDocumentUpdate(document, { addService: { ...NEW_SERVICE } })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'service_exists' });
  });

  it('既にある controller の追加は 2010(controller_exists)', () => {
    const document = { ...baseDocument(), controller: 'did:stub:controller' };
    expect(
      failureOf(() => applyDidDocumentUpdate(document, { addController: 'did:stub:controller' })),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'controller_exists' });
  });
});
