/**
 * `verifyJarSignature` の `rpCertJudgmentCache` 配線の回帰テスト。
 *
 * RP Cert 判定結果（Trust Anchor 到達 + 失効チェック）の TTL キャッシュ自体の単体テストは
 * `trust/rp-access/__tests__/cache.test.ts` が担う。本ファイルは `jar-signature.ts` の
 * `requireTrustedSigner` がそのキャッシュを正しく使うこと（ヒット時はチェーン検証を
 * 再実行しない・キーが変われば再検証する）だけを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { makeRpCertificate } from '../../../trust/rp-access/__tests__/fixtures.js';
import {
  createRpCertJudgmentCache,
  readRpCertJudgment,
  rpCertJudgmentCacheKey,
} from '../../../trust/rp-access/cache.js';
import { verifyJarSignature } from '../jar-signature.js';
import { CLIENT_ID, jarClaims, makeJarSigner, signJar, toX5cEntry } from './jar-fixtures.js';

async function expectReason(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

describe('verifyJarSignature: rpCertJudgmentCache', () => {
  it('省略時はキャッシュを使わず従来どおり毎回検証する（既定動作は変わらない）', async () => {
    const verifier = makeJarSigner();
    const jar = signJar(verifier);
    await expect(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors }),
    ).resolves.toBeUndefined();
  });

  describe('TTL は証明書の有効期間で頭打ちになる', () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    // Request Object の有効期限を十分先に設定し、証明書の期限だけを検証する。
    const farExp = jarClaims({ exp: nowSeconds + 86_400 });

    async function verifyAt(
      verifier: ReturnType<typeof makeJarSigner>,
      cache: ReturnType<typeof createRpCertJudgmentCache>,
      at: number,
    ): Promise<void> {
      await verifyJarSignature(signJar(verifier, { claims: farExp }), {
        trustAnchors: verifier.anchors,
        rpCertJudgmentCache: cache,
        now: at,
      });
    }

    it('成功は leaf の notAfter を超えてヒットしない（固定 45 分より短い有効期間）', async () => {
      const verifier = makeJarSigner({ notAfter: new Date((nowSeconds + 600) * 1000) });
      const cache = createRpCertJudgmentCache();

      await verifyAt(verifier, cache, nowSeconds);
      // 45 分 TTL 内だが notAfter を過ぎた基準時刻: ヒットせず再検証され、期限切れで拒否される。
      await expectReason(verifyAt(verifier, cache, nowSeconds + 601), 'rp_cert_untrusted');
    });

    it('成功は Trust Anchor（CA）の notAfter でも頭打ちになる', async () => {
      const verifier = makeJarSigner({ caNotAfter: new Date((nowSeconds + 600) * 1000) });
      const cache = createRpCertJudgmentCache();

      await verifyAt(verifier, cache, nowSeconds);
      await expectReason(verifyAt(verifier, cache, nowSeconds + 601), 'rp_cert_untrusted');
    });

    it('有効期間内であればヒットし、以前の成功結果を返す', async () => {
      const verifier = makeJarSigner({ notAfter: new Date((nowSeconds + 3600) * 1000) });
      const cache = createRpCertJudgmentCache();
      const key = rpCertJudgmentCacheKey(verifier.rp.der, [], verifier.anchors, undefined);

      await verifyAt(verifier, cache, nowSeconds);

      expect(readRpCertJudgment(cache, key, nowSeconds + 1800)).toBe(true);
      expect(readRpCertJudgment(cache, key, nowSeconds + 3601)).toBeUndefined();
    });

    it('notBefore 前の失敗は有効になった後も残らない', async () => {
      const verifier = makeJarSigner({ notBefore: new Date((nowSeconds + 600) * 1000) });
      const cache = createRpCertJudgmentCache();

      await expectReason(verifyAt(verifier, cache, nowSeconds), 'rp_cert_untrusted');
      // 45 分 TTL 内だが notBefore を過ぎた基準時刻: 失敗はヒットせず、再検証で成功する。
      await verifyAt(verifier, cache, nowSeconds + 601);
    });
  });

  it('対照実験: キャッシュを渡さなければ有効期間切れの基準時刻で失敗する', async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const verifier = makeJarSigner({ notAfter: new Date((nowSeconds + 3600) * 1000) });
    const jar = signJar(verifier);
    await expectReason(
      verifyJarSignature(jar, {
        trustAnchors: verifier.anchors,
        now: nowSeconds + 7200,
      }),
      'rp_cert_untrusted',
    );
  });

  it('revokedSerials が変化するとキャッシュキーが変わり再検証される（失効を見逃さない）', async () => {
    const verifier = makeJarSigner();
    const jar = signJar(verifier);
    const cache = createRpCertJudgmentCache();

    // 1 回目: 失効情報なし → 成功しキャッシュされる。
    await expect(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors, rpCertJudgmentCache: cache }),
    ).resolves.toBeUndefined();

    // 2 回目: 同じ証明書・同じ anchors だが、この証明書のシリアル（フィクスチャは 101 = `65`）を
    // 失効集合に含めて渡す。`revokedSerials` はキャッシュキーに含まれるため別エントリになり、
    // 実際に再検証されて失効判定が効く（古い valid:true がそのまま配られない）。
    await expectReason(
      verifyJarSignature(jar, {
        trustAnchors: verifier.anchors,
        rpCertJudgmentCache: cache,
        revokedSerials: new Set(['65']),
      }),
      'rp_cert_untrusted',
    );
  });

  it('trustAnchors 集合が変化するとキャッシュキーが変わり再検証される', async () => {
    const verifier = makeJarSigner();
    const jar = signJar(verifier);
    const cache = createRpCertJudgmentCache();
    const foreign = makeJarSigner();

    await expect(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors, rpCertJudgmentCache: cache }),
    ).resolves.toBeUndefined();

    // 別 Trust Anchor 集合（無関係な CA）を渡すと、anchors の指紋が変わるためキャッシュミスし、
    // 実際に再検証されて到達しない Trust Anchor として拒否される。
    await expectReason(
      verifyJarSignature(jar, { trustAnchors: foreign.anchors, rpCertJudgmentCache: cache }),
      'rp_cert_untrusted',
    );
  });

  it('パース不能な証明書は従来どおり拒否し、再送しても同じ結果になる', async () => {
    const verifier = makeJarSigner();
    const cache = createRpCertJudgmentCache();
    const brokenDer = toX5cEntry(Uint8Array.from([0x00, 0x01, 0x02]));
    const jar = signJar(verifier, { header: { x5c: [brokenDer] } });
    await expectReason(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors, rpCertJudgmentCache: cache }),
      'rp_cert_untrusted',
    );
    await expectReason(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors, rpCertJudgmentCache: cache }),
      'rp_cert_untrusted',
    );
  });

  describe('同一シリアルの偽造 x5c', () => {
    /** 正規 RP と同じシリアル・同じ SAN の自己署名証明書を `x5c` に載せた JAR 用の署名者。 */
    function forgedSigner(legit: ReturnType<typeof makeJarSigner>) {
      const forged = makeRpCertificate({
        subject: { organizationName: 'Evil', country: 'DE' },
        kind: 'ec',
        origin: CLIENT_ID,
        serial: 101,
      });
      return { ...legit, rp: forged };
    }

    it('正規証明書の成功がキャッシュされていても、偽造証明書はキャッシュにヒットせず拒否される', async () => {
      const legit = makeJarSigner();
      const cache = createRpCertJudgmentCache();
      await expect(
        verifyJarSignature(signJar(legit), {
          trustAnchors: legit.anchors,
          rpCertJudgmentCache: cache,
        }),
      ).resolves.toBeUndefined();

      const forgedJar = signJar(forgedSigner(legit));
      await expectReason(
        verifyJarSignature(forgedJar, { trustAnchors: legit.anchors, rpCertJudgmentCache: cache }),
        'rp_cert_untrusted',
      );
    });

    it('偽造証明書の失敗をキャッシュに先に載せても、正規証明書は拒否されない（キャッシュ汚染 DoS）', async () => {
      const legit = makeJarSigner();
      const cache = createRpCertJudgmentCache();
      await expectReason(
        verifyJarSignature(signJar(forgedSigner(legit)), {
          trustAnchors: legit.anchors,
          rpCertJudgmentCache: cache,
        }),
        'rp_cert_untrusted',
      );
      await expect(
        verifyJarSignature(signJar(legit), {
          trustAnchors: legit.anchors,
          rpCertJudgmentCache: cache,
        }),
      ).resolves.toBeUndefined();
    });
  });
});
