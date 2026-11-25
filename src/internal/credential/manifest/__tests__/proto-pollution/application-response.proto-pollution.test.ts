/**
 * `processCredentialResponse`（DIF Credential Response）の `Object.prototype` 汚染耐性
 *
 * `raw` は Issuer 応答を `JSON.parse` した結果（`application.ts` の `submitCredentialApplication`
 * 経由）であり `Object.prototype` を継承する。応答メンバを鎖読みすると **Issuer が `{}` を
 * 返しただけで**汚染値が採用され、それぞれ別の実害になる。
 *
 * - `transaction_id` / `transactionId`: 空応答が**遅延発行に化ける**。呼び出し側は攻撃者が
 *   指す取引 ID をポーリングする。
 * - `denial` / `rejectionReason`: **正常な応答が却下に化ける**。denial は fulfillment より先に
 *   判定されるため、`credential` を含む正当な応答すら却下として返る（可用性の毀損）。
 * - `verifiableCredential` / `credential`: 汚染値が受領 VC 文字列として `verify` へ渡る。
 *
 * `isNonBlankString` / `isPlainObject` のガードは汚染値が空白のみでない文字列 / オブジェクトであれば
 * 素通りするため防げない。
 *
 * テストは**キーを 1 つずつ単独で汚染する**。まとめて汚染すると 1 行を鎖読みへ戻しても別の行が
 * 先に落ちてしまい、「この 1 行を戻すとこのテストが落ちる」という mutation check が成立しない。
 * `processCredentialResponse` は async なので `withPollutedPrototype*Async` を使う（同期版は
 * `fn` の返す Promise の解決前に汚染を戻すため、検証したい経路が汚染下で走らない）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { processCredentialResponse } from '../../application-response.js';
import type { ApplicationResult } from '../../types.js';

const ATTACKER_VC = 'eyJhbGciOiJFUzI1NiJ9.attacker-vc';
const ATTACKER_REASON = 'attacker-controlled rejection';
const ATTACKER_TX = 'tx-attacker';
const HONEST_VC = 'eyJhbGciOiJFUzI1NiJ9.honest-vc';
const HONEST_REASON = 'insufficient evidence';
const HONEST_TX = 'tx-issuer-1';

const VERIFIED_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  id: 'urn:vc:issued',
};

/** 受け取った生 VC を記録する `verify` DI（汚染値が検証へ流れたかを観測する）。 */
function recordingVerify(): { fn: (raw: string) => Promise<VerifiableCredential>; seen: string[] } {
  const seen: string[] = [];
  return {
    seen,
    fn: async (raw: string) => {
      seen.push(raw);
      return VERIFIED_VC;
    },
  };
}

/** 汚染キー 1 つと、そのキーを own プロパティとして持たない応答の組。 */
interface OwnReadCase {
  /** 単独で汚染するキー。 */
  readonly key: string;
  /** 汚染値。 */
  readonly value: unknown;
  /** Issuer の応答（`key` を own プロパティとして持たない）。 */
  readonly response: Record<string, unknown>;
  /** 鎖読みだと何に化けるか（テスト名に出す）。 */
  readonly harm: string;
}

const OWN_READ_CASES: readonly OwnReadCase[] = [
  { key: 'denial', value: { reason: ATTACKER_REASON }, response: {}, harm: '却下' },
  // 外側 `denial` だけ own 化しても内側 `reason` に穴が残るため、内側も単独で固定する。
  { key: 'reason', value: ATTACKER_REASON, response: { denial: {} }, harm: '却下' },
  { key: 'rejectionReason', value: ATTACKER_REASON, response: {}, harm: '却下' },
  { key: 'verifiableCredential', value: ATTACKER_VC, response: {}, harm: '即時発行' },
  { key: 'credential', value: ATTACKER_VC, response: {}, harm: '即時発行' },
  { key: 'transaction_id', value: ATTACKER_TX, response: {}, harm: '遅延発行' },
  { key: 'transactionId', value: ATTACKER_TX, response: {}, harm: '遅延発行' },
];

describe('processCredentialResponse: Credential Response の Object.prototype 汚染耐性', () => {
  for (const testCase of OWN_READ_CASES) {
    const title = `${testCase.key} の汚染で応答が${testCase.harm}に化けない`;

    it(`${title}（データ汚染）`, async () => {
      const verify = recordingVerify();
      await withPollutedPrototypeAsync({ [testCase.key]: testCase.value }, async () => {
        await expect(processCredentialResponse(testCase.response, verify.fn)).rejects.toMatchObject(
          { code: ErrorCodes.MANIFEST_SCHEMA_INVALID },
        );
      });
      // 汚染値が受領 VC として検証へ渡っていないこと。
      expect(verify.seen).toEqual([]);
    });

    it(`${title}（アクセサ汚染）`, async () => {
      const verify = recordingVerify();
      await withPollutedPrototypeAccessorAsync(
        { [testCase.key]: () => testCase.value },
        async () => {
          await expect(
            processCredentialResponse(testCase.response, verify.fn),
          ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_SCHEMA_INVALID });
        },
      );
      expect(verify.seen).toEqual([]);
    });
  }
});

/**
 * 汚染下でも Issuer が**実際に返した**メンバは従来どおり採用されること（非退行）。
 *
 * own 化が「常に 3031 へ倒れるだけ」の退行になっていないことを示すため、全キーを汚染した状態で
 * 正当な応答 3 形（却下 / 即時発行 / 遅延発行）がそれぞれ本来の結果になることを確認する。
 *
 * あわせて戻り値が `ApplicationResult` の 4 キーを**自身のプロパティとして**持つことも固定する。
 * 条件付きスプレッドでキーを落とすと、呼び出し側の `result.credential` 等が汚染された
 * `Object.prototype` へ到達し、ここまでの own 化が repack で丸ごと無効化される。
 * `result` は汚染解除後に検査されるため、`expect(result.credential).toBeUndefined()` では
 * キーが無くても通ってしまう（トートロジー）。キーの**存在**を `Object.hasOwn` で見る。
 */
describe('processCredentialResponse: 汚染下でも Issuer の応答をそのまま採用する', () => {
  const ALL_POLLUTED = {
    denial: { reason: ATTACKER_REASON },
    reason: ATTACKER_REASON,
    rejectionReason: ATTACKER_REASON,
    verifiableCredential: ATTACKER_VC,
    credential: ATTACKER_VC,
    transaction_id: ATTACKER_TX,
    transactionId: ATTACKER_TX,
  };
  const ALL_POLLUTED_GETTERS = Object.fromEntries(
    Object.entries(ALL_POLLUTED).map(([key, value]) => [key, () => value]),
  );

  /** 汚染を仕込んだまま `fn` を await するランナー（データ汚染 / アクセサ汚染）。 */
  type PollutionRunner = (fn: () => Promise<ApplicationResult>) => Promise<ApplicationResult>;
  const FORMS: readonly (readonly [string, PollutionRunner])[] = [
    ['データ汚染', (fn) => withPollutedPrototypeAsync(ALL_POLLUTED, fn)],
    ['アクセサ汚染', (fn) => withPollutedPrototypeAccessorAsync(ALL_POLLUTED_GETTERS, fn)],
  ];

  /** 4 キーが値の有無に関わらず own プロパティとして定義されていること。 */
  function expectAllMembersOwn(result: ApplicationResult): void {
    for (const key of ['accepted', 'transactionId', 'credential', 'rejectionReason']) {
      expect(Object.hasOwn(result, key)).toBe(true);
    }
  }

  for (const [form, run] of FORMS) {
    it(`denial.reason を返した応答は Issuer の理由で却下になる（${form}）`, async () => {
      const verify = recordingVerify();
      const result = await run(async () =>
        processCredentialResponse({ denial: { reason: HONEST_REASON } }, verify.fn),
      );
      expect(result).toMatchObject({ accepted: false, rejectionReason: HONEST_REASON });
      expectAllMembersOwn(result);
    });

    it(`credential を返した応答は Issuer の VC を検証して受理する（${form}）`, async () => {
      const verify = recordingVerify();
      const result = await run(async () =>
        processCredentialResponse({ credential: HONEST_VC }, verify.fn),
      );
      expect(verify.seen).toEqual([HONEST_VC]);
      expect(result).toMatchObject({ accepted: true, credential: VERIFIED_VC });
      expectAllMembersOwn(result);
    });

    it(`transaction_id を返した応答は Issuer の取引 ID で遅延発行になる（${form}）`, async () => {
      const verify = recordingVerify();
      const result = await run(async () =>
        processCredentialResponse({ transaction_id: HONEST_TX }, verify.fn),
      );
      expect(result).toMatchObject({ accepted: true, transactionId: HONEST_TX });
      expectAllMembersOwn(result);
    });
  }
});
