/**
 * `options.cache` 形状検証（`isValidTrustedListCache`、`cache.ts`）の `Object.prototype` 汚染耐性
 * テスト。
 *
 * `isValidTrustedListCache` は `cache.get` / `cache.set` を**プロトタイプ鎖読み**（`cache.get` の
 * 素のドット参照）で検査していた。`cache-guard.test.ts` の不正形状ケース（`{}` 等）はいずれも
 * `Object.prototype` が汚染されていない前提のテストであり、汚染下でこのガード自体が破られる欠陥は
 * 別に固定する必要がある。
 *
 * `Object.prototype.get` / `Object.prototype.set` が汚染されていると、呼び出し側が `cache: {}`
 * （own プロパティを一切持たない不正な形状）を渡しても `cache.get` / `cache.set` が鎖経由で
 * 攻撃者の関数に解決され、ガードを素通りする。その結果 `readTrustedListCache` が攻撃者の
 * `get` 実装をそのまま呼び出し、**攻撃者が自己署名した TSL**（`verifyXmlDsig` は埋め込み証明書での
 * 署名検証のみを行い、上位 Trust Anchor への連結は判定しない）を「有効期限内のキャッシュ」として
 * FO-5 に渡してしまう。攻撃者 CA が granted な Trust Anchor として警告付きで通過するため、
 * `verifyQualifiedCertificate` が攻撃者発行のリーフ証明書を信頼し得る。
 *
 * `nonObjectPrototypeProperty` へ切り替えた修正後は、`cache: {}` の `get` / `set` が
 * `Object.prototype` 由来と判定されてガードが `false` を返し、攻撃者の `get` は一切呼ばれず
 * 「キャッシュ無し」として fail-closed になることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import type { TrustedListCache } from '../../cache.js';
import { type LoadTrustedListOptions, loadTrustedList } from '../../etsi-tsl.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const TSL_URL = 'https://tsl.example/DE.xml';
const NOW_SECONDS = 1_700_000_000;

/**
 * `Object.prototype.get` / `Object.prototype.set` を**同時に**仕込み、必ず元へ戻す。
 *
 * 共有フィクスチャ（`prototype-pollution.fixtures.ts` の `withPollutedPrototypeAsync`）は
 * キーごとに `Object.defineProperty` を個別に呼ぶが、`get` → `set` の順で個別定義すると Bun
 * （JavaScriptCore）が `"'value' present on property with getter or setter"` を投げる
 * （`get` / `set` という名前の組み合わせに限った実装依存の挙動。実機で再現確認済み。
 * `Object.defineProperties` による一括定義には現れない）。本テストは検証対象そのものが
 * `get` / `set` の同時汚染であるため、共有フィクスチャを流用せずこの形だけ個別に用意する。
 */
async function withPollutedGetSet<T>(
  get: () => unknown,
  set: () => void,
  fn: () => Promise<T>,
): Promise<T> {
  const proto = Object.prototype as unknown as Record<string, unknown>;
  if (Object.hasOwn(proto, 'get') || Object.hasOwn(proto, 'set')) {
    throw new Error('prototype pollution fixture would clobber Object.prototype.get/set');
  }
  Object.defineProperties(proto, {
    get: { value: get, writable: true, configurable: true, enumerable: false },
    set: { value: set, writable: true, configurable: true, enumerable: false },
  });
  try {
    return await fn();
  } finally {
    delete proto.get;
    delete proto.set;
  }
}

/** 攻撃者が自己署名した「granted」TSL。署名検証（埋め込み証明書ベース）は通ってしまう。 */
function attackerSignedTslXml(): string {
  const attackerCa = makeCertificate({ cn: 'Attacker CA', kind: 'rsa' });
  const attackerSigner = makeCertificate({ cn: 'Attacker TSL Signer', kind: 'ec' });
  const bodyInner =
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    `<X509Certificate>${base64.encode(attackerCa.der)}</X509Certificate></TSPService>`;
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: attackerSigner.privateKey,
    certDer: attackerSigner.der,
    kind: 'ec',
  });
}

describe('options.cache の形状検証 汚染耐性（isValidTrustedListCache）', () => {
  it('継承した cache.get / cache.set では、攻撃者の自己署名 TSL が有効なキャッシュとして受理されない', async () => {
    const records: FailSafeAuditRecord[] = [];
    const attackerEntry: TrustedListCache = {
      url: TSL_URL,
      type: 'tsl',
      xml: attackerSignedTslXml(),
      signatureValid: true,
      nextUpdate: new Date((NOW_SECONDS + 3600) * 1000).toISOString(),
      fetchedAt: new Date(NOW_SECONDS * 1000).toISOString(),
    };

    const deps: LoadTrustedListOptions = {
      kind: 'tsl',
      // own プロパティを一切持たない不正な形状。`get` / `set` は `Object.prototype` 汚染でのみ解決される。
      cache: {} as never,
      nowSeconds: NOW_SECONDS,
      fetcher: async () => {
        throw new Error('network');
      },
      failOpenWindow: createFailOpenWindow(),
      requestConsent: (): boolean => true,
      onPolicyEvent: (record: FailSafeAuditRecord): void => {
        records.push(record);
      },
    };

    let caught: unknown;
    await withPollutedGetSet(
      (): { value: TrustedListCache; expired: boolean } => ({
        value: attackerEntry,
        expired: false,
      }),
      (): void => {
        throw new Error('攻撃者の set が呼ばれた（own 限定読みが機能していない）');
      },
      async () => {
        try {
          await loadTrustedList(TSL_URL, deps);
        } catch (error) {
          caught = error;
        }
      },
    );

    // 攻撃者の CA が Trust Anchor として通ってしまう（＝解決に成功する）のではなく、
    // 「キャッシュ無し」と同じ fail-closed（TSL_FETCH_FAILED）に倒れることを固定する。
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TSL_FETCH_FAILED);
    expect(records).toEqual([]);
  });
});
