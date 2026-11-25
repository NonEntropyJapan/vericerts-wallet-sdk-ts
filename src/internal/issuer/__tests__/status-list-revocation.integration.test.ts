/**
 * 失効運用フロー（VC 発行 → revoke → 再署名 → Verifier 検出）の回帰テスト
 * （実鍵・実圧縮・モック禁止）。
 *
 * Issuer Service の `/status/{listId}` / `/revoke` 相当の流れを、issuer ドメインの運用ヘルパーと
 * credential ドメイン（`createSdJwt` / `verifySdJwt` / `resolveStatus`）を実際に通してエンド
 * ツーエンドに再現する:
 * 1. 新規 status list を作成し、VC 発行時に idx を割り当てて status 参照を得る。
 * 2. その status 参照を埋め込んだ SD-JWT VC を発行し、検証して payload から status を取り出す
 *    （VC への埋め込み〜抽出の往復も実際に通す）。
 * 3. Status List Token を発行し、Verifier が valid と判定する。
 * 4. revoke → 再署名した Token を配信する。
 * 5. 再取得した Verifier が、VC から取り出した status で失効を検出する。
 *
 * 併せて TTL 上限が失効反映の遅延上界を決めることを検証する。SDK にキャッシュ層は存在しない
 * （`status-list-resolver.ts` は毎回 `fetchToken` する）ため、`evaluateCacheFreshness` が fresh
 * の間は再取得しない簡易キャッシュを本ファイル内のローカルヘルパとして組み、同一キャッシュ
 * インスタンス経由で (a) TTL 内は revoke 後も `valid` のままで再取得しないこと (b) TTL 経過後は
 * 再取得して `revoked` になること を確認する。加えて `evaluateCacheFreshness` 単体の TTL 切り詰め
 * 算術も検証する。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt, type StatusReference } from '../../credential/sdjwt/sdjwt.js';
import { resolveStatus, type StatusCheckResult } from '../../credential/sdjwt/status.js';
import { verifySdJwt } from '../../credential/sdjwt/verify.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { getP256PublicKey } from '../../keymanager/signer.js';
import { createStatusListResolver } from '../status-list-resolver.js';
import {
  assertStatusValid,
  evaluateCacheFreshness,
  evaluateStatusEntry,
} from '../status-list-verifier.js';
import { createStatusList, StatusListManager } from '../token-status-list.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const URI = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';
const ISSUED_AT = 1_700_000_000;
const SLA_SECONDS = 60;
const VCT = 'https://issuer.example/vct/employee';

const ISSUER_JWK: PublicKeyJwk = (() => {
  const pub = getP256PublicKey(ISSUER_KEY, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
})();

/** 与えた token を URI に紐付けて配信する fetchToken を作る。 */
function serve(token: string): (uri: string) => Promise<string> {
  return async (uri: string) => {
    if (uri !== URI) {
      throw new Error('unknown status list uri');
    }
    return token;
  };
}

/**
 * 配信中の token を Verifier として評価する。
 *
 * `nowSeconds` を固定する（既定のシステム時刻を使わない）。本テストの token は `ISSUED_AT`
 * （固定の過去時刻）基準で発行されるため、実時刻で評価すると常に `exp` 超過となり、
 * 新規取得した期限切れ Token を拒否する規定に掛かってしまう。
 */
function verifierFor(token: string, nowSeconds: number = ISSUED_AT) {
  return createStatusListResolver({
    fetchToken: serve(token),
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    nowSeconds: () => nowSeconds,
  });
}

/** 配信中の token を差し替えられ、取得回数を数える配信元（Issuer の `/status/{listId}` 相当）。 */
function createOrigin(initialToken: string) {
  let current = initialToken;
  let fetchCount = 0;
  return {
    /** 再署名した token を配信に載せ替える。 */
    serve(token: string): void {
      current = token;
    },
    /** これまでに配信元へ取りに行った回数。 */
    get fetchCount(): number {
      return fetchCount;
    },
    async fetchToken(uri: string): Promise<string> {
      if (uri !== URI) {
        throw new Error('unknown status list uri');
      }
      fetchCount += 1;
      return current;
    },
  };
}

/**
 * `evaluateCacheFreshness` が fresh の間は配信元へ取りに行かない簡易キャッシュ Verifier。
 *
 * SDK にキャッシュ層は無いため、評価プリミティブを使って本ファイル内で組み立てる
 * （SDK 本体へ新しい export は足さない）。
 */
function createCachingVerifier(origin: ReturnType<typeof createOrigin>, ttlSeconds: number) {
  let cached: { token: string; fetchedAtSeconds: number } | undefined;
  return {
    /** `nowSeconds` 時点でキャッシュを評価し、必要なら再取得してから status を解決する。 */
    async resolveAt(status: StatusReference, nowSeconds: number): Promise<StatusCheckResult> {
      const current = cached;
      const fresh =
        current !== undefined &&
        evaluateCacheFreshness({
          fetchedAtSeconds: current.fetchedAtSeconds,
          nowSeconds,
          maxTtlSeconds: ttlSeconds,
        }).fresh;
      const entry =
        current !== undefined && fresh
          ? current
          : { token: await origin.fetchToken(URI), fetchedAtSeconds: nowSeconds };
      cached = entry;
      return resolveStatus(status, verifierFor(entry.token, nowSeconds));
    },
  };
}

describe('失効運用フロー: 発行 → revoke → 再署名 → 検出', () => {
  it('失効済み VC を Verifier が revoked として検出する', async () => {
    // 1. 新規 status list 作成と VC 発行時の idx 割り当て。
    const list = createStatusList({ uri: URI, issuer: ISSUER, size: 1024, bits: 1 });
    const { idx, status } = list.allocateEntry();
    expect(status).toEqual({ status_list: { idx, uri: URI } });

    // 2. status 参照入りの SD-JWT VC を発行し、検証して payload から status を取り出す。
    const sdJwt = createSdJwt(SIGNER, {
      vct: VCT,
      disclosureClaims: ['nickname'],
      claims: { nickname: 'saya', employee_id: 'E-001' },
      status,
      issuer: ISSUER,
      nowSeconds: ISSUED_AT,
    });
    const verified = verifySdJwt(sdJwt, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      nowSeconds: ISSUED_AT,
    });
    // VC payload への埋め込み〜抽出で参照が保たれる（以降はこの取り出した status で評価する）。
    expect(verified.status).toEqual({ status_list: { idx, uri: URI } });
    const vcStatus = verified.status;

    // 3. Token を配信し、Verifier は valid と判定する。
    let served = await list.issueToken(SIGNER, { iatSeconds: ISSUED_AT, ttlSeconds: SLA_SECONDS });
    const before = await resolveStatus(vcStatus, verifierFor(served));
    expect(evaluateStatusEntry(before)).toBe('valid');
    expect(() => assertStatusValid(before)).not.toThrow();

    // 4. 失効指示 → 再署名した Token を配信する。
    list.revoke(idx);
    expect(list.isSet(idx)).toBe(true);
    served = await list.issueToken(SIGNER, {
      iatSeconds: ISSUED_AT + 1,
      ttlSeconds: SLA_SECONDS,
    });

    // 5. TTL 切れで再取得した Verifier は VC 由来の status で失効を検出する。
    const stale = evaluateCacheFreshness({
      fetchedAtSeconds: ISSUED_AT,
      nowSeconds: ISSUED_AT + SLA_SECONDS,
      maxTtlSeconds: SLA_SECONDS,
    });
    expect(stale.fresh).toBe(false);

    const after = await resolveStatus(vcStatus, verifierFor(served));
    expect(after).toEqual({ valid: false, purpose: 'revocation', value: 1 });
    expect(evaluateStatusEntry(after)).toBe('revoked');
    try {
      assertStatusValid(after);
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_REVOKED);
    }
  });

  it('失効させた VC 以外は valid のまま（巻き添え失効しない）', async () => {
    const list = createStatusList({ uri: URI, issuer: ISSUER, size: 1024, bits: 1 });
    const revoked = list.allocateEntry();
    const kept = list.allocateEntry();
    list.revoke(revoked.idx);

    const token = await list.issueToken(SIGNER, { iatSeconds: ISSUED_AT });
    const resolver = verifierFor(token);
    expect(evaluateStatusEntry(await resolveStatus(revoked.status, resolver))).toBe('revoked');
    expect(evaluateStatusEntry(await resolveStatus(kept.status, resolver))).toBe('valid');
  });

  it('TTL 内は古いキャッシュで失効が見えず、TTL 経過後に revoked になる', async () => {
    const list = createStatusList({ uri: URI, issuer: ISSUER, size: 1024, bits: 1 });
    const { idx, status } = list.allocateEntry();
    const origin = createOrigin(await list.issueToken(SIGNER, { iatSeconds: ISSUED_AT }));
    const verifier = createCachingVerifier(origin, SLA_SECONDS);

    // 初回は配信元から取得して valid。
    expect(evaluateStatusEntry(await verifier.resolveAt(status, ISSUED_AT))).toBe('valid');
    expect(origin.fetchCount).toBe(1);

    // 失効指示 → 再署名した Token を配信に載せ替える。
    list.revoke(idx);
    origin.serve(await list.issueToken(SIGNER, { iatSeconds: ISSUED_AT + 1 }));

    // (a) TTL が残っている間は再取得しないため、失効はまだ見えない。
    const withinTtl = await verifier.resolveAt(status, ISSUED_AT + SLA_SECONDS - 1);
    expect(evaluateStatusEntry(withinTtl)).toBe('valid');
    expect(origin.fetchCount).toBe(1);

    // (b) TTL 経過後は同一キャッシュインスタンスが再取得し、失効が反映される。
    const afterTtl = await verifier.resolveAt(status, ISSUED_AT + SLA_SECONDS);
    expect(evaluateStatusEntry(afterTtl)).toBe('revoked');
    expect(origin.fetchCount).toBe(2);
  });

  it('TTL 上限が失効反映の遅延上界を決める（SLA 内は再取得しない）', () => {
    // 配信側が 1 日の max-age を返しても、呼び出し側指定の上限 60 秒で切り詰められる。
    const fresh = evaluateCacheFreshness({
      fetchedAtSeconds: ISSUED_AT,
      nowSeconds: ISSUED_AT + 59,
      maxAgeSeconds: 86_400,
      maxTtlSeconds: SLA_SECONDS,
    });
    expect(fresh.fresh).toBe(true);
    expect(fresh.effectiveTtlSeconds).toBe(SLA_SECONDS);
    expect(fresh.remainingSeconds).toBe(1);

    const expired = evaluateCacheFreshness({
      fetchedAtSeconds: ISSUED_AT,
      nowSeconds: ISSUED_AT + SLA_SECONDS,
      maxAgeSeconds: 86_400,
      maxTtlSeconds: SLA_SECONDS,
    });
    expect(expired.fresh).toBe(false);
  });

  it('再起動を挟んでも失効状態と払い出し済み idx を引き継ぐ', async () => {
    const list = createStatusList({ uri: URI, issuer: ISSUER, size: 1024, bits: 1 });
    const { idx, status } = list.allocateEntry();
    list.revoke(idx);

    // 永続化 → 再起動相当の復元。
    const restored = await StatusListManager.restore(await list.snapshot());
    // 復元後に払い出す idx は既存 VC と衝突しない。
    expect(restored.allocate()).toBe(1);

    const token = await restored.issueToken(SIGNER, { iatSeconds: ISSUED_AT });
    const result = await resolveStatus(status, verifierFor(token));
    expect(evaluateStatusEntry(result)).toBe('revoked');
  });
});
