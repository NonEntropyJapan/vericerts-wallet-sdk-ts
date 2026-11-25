/**
 * RP Access Certificate 検証の高レベル API（trust/rp-access）。
 *
 * ETSI TS 119 475 の RP Access
 * Certificate を (1) パース、(2) TSL 由来 Trust Anchor へのチェーン検証、(3) 有効期間、
 * (4) Trusted List ベースの失効チェック、(5) 属性 / 目的 / カテゴリの権限マッチング、
 * (6) Cross-border 判定、の順で検証し、構造化結果を返す。
 *
 * TSL 連携: Trust Anchor は etsi-tsl の `QtspServiceCertificate`（granted）を受け取り、
 * `verifyCertificateChain` でチェーンを検証する。失効は TSL の granted 集合に Anchor が残って
 * いるか（Trusted List Status）で判定する（CRL/OCSP は本スコープ外）。失効集合
 * （`revokedSerials`）が渡されない場合は**未確認**（`revocation.checked: false` /
 * `method: 'none'`）を返し、確認していない失効状態を「確認済み」と主張しない。
 *
 * セキュリティ上の注意:
 * - fail-closed。パース不能・チェーン不成立・有効期間外・失効はいずれも `valid:false`。
 * - 例外は投げず結果に正規化する（呼び出し側 facade が必要に応じて VericertsError 化する）。
 * - 結果・ログに証明書本文 / 鍵素材を含めない。
 */

import { ErrorCodes } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { verifyCertificateChain } from '../etsi-tsl/chain.js';
import { grantedTrustAnchors, type QtspServiceCertificate } from '../etsi-tsl/tsl.js';
import { derEquals } from '../etsi-tsl/x509.js';
import { allClaimsAuthorized, authorizeClaims, isCrossBorder } from './authorization.js';
import { parseRpAccessCertificate } from './cert.js';
import type {
  ClaimAuthorization,
  RequestedClaim,
  RevocationStatus,
  RpAccessVerificationResult,
  RpDescriptor,
  TrustChainNode,
} from './types.js';

/** `verifyRpAccessCertificate` のオプション。 */
export interface VerifyRpAccessOptions {
  /** RP Access Certificate の DER。 */
  readonly certDer: Uint8Array;
  /** RP が要求する属性群。 */
  readonly requestedClaims: readonly RequestedClaim[];
  /** TSL から抽出した QTSP サービス証明書（Trust Anchor 候補）。 */
  readonly trustAnchors: readonly QtspServiceCertificate[];
  /** チェーンを辿る中間 CA 証明書 DER（任意）。 */
  readonly intermediatesDer?: readonly Uint8Array[];
  /**
   * Trusted List Status で失効と判定された RP 証明書のシリアル番号（16 進・小文字）。
   * `subscribeRpAccessCertificateRevocation` が維持する集合を渡す。
   *
   * 省略時は失効情報源が無いため**未確認**として扱い、結果の `revocation` は
   * `checked: false` / `method: 'none'` になる（「失効なしを確認した」とは主張しない）。
   */
  readonly revokedSerials?: ReadonlySet<string>;
  /** 検証基準時刻（Unix 秒・任意。既定は現在時刻）。 */
  readonly now?: number;
}

/**
 * Unix 秒を ISO 8601 文字列にする。表現できない値（NaN / Infinity / Date 範囲外）は `Invalid Date` の
 * RangeError になるため、実時計へ倒す（`checkedAt` は「実際に確認した時刻」。そのような基準時刻自体は
 * 有効期間検査が `RP_ACCESS_CERT_OUT_OF_VALIDITY` に倒す）。
 */
function toIso(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  return (Number.isNaN(date.getTime()) ? new Date() : date).toISOString();
}

/** 有効期間外の要求属性判定に使う「全拒否」の ClaimAuthorization を作る。 */
function denyAll(requested: readonly RequestedClaim[], reason: string): ClaimAuthorization[] {
  return requested.map((c) => ({
    claimPath: c.claimPath,
    authorized: false,
    purposeAligned: false,
    categoryAllowed: false,
    reason,
  }));
}

/**
 * 失効状態を組み立てる（Trusted List ベース）。
 *
 * `revokedSerials` 未指定時は参照できる失効情報源が無く、実際には何も確認していない。
 * ここで `checked: true` / `method: 'trusted-list'` を返すと「失効確認済み」という
 * 事実に反する主張になるため、`checked: false` / `method: 'none'`（未確認）を返す。
 */
function revocationStatus(
  revokedSerials: ReadonlySet<string> | undefined,
  serialHex: string,
  now: number,
): RevocationStatus {
  if (revokedSerials === undefined) {
    return { checked: false, revoked: false, method: 'none', checkedAt: toIso(now) };
  }
  return {
    checked: true,
    revoked: revokedSerials.has(serialHex),
    method: 'trusted-list',
    checkedAt: toIso(now),
  };
}

/**
 * RP Access Certificate を検証する。
 *
 * @param options 証明書 DER・要求属性・Trust Anchor・中間証明書・基準時刻。
 * @returns 構造化検証結果。パース不能な入力は `valid:false`（空の RP 記述子）を返す。
 */
export async function verifyRpAccessCertificate(
  options: VerifyRpAccessOptions,
): Promise<RpAccessVerificationResult> {
  // 任意オプションは自身のプロパティに限って読む。継承した `now` は証明書の
  // 有効期間検証を攻撃者が選んだ時刻で行わせ、期限切れの RP Access Certificate を通す。
  const now = ownProperty<number>(options, 'now') ?? Math.floor(Date.now() / 1000);
  // 同一関数内で読み方を揃える。`revokedSerials` が鎖読みのままだと、失効情報源を
  // **渡していない**呼び出しで汚染値が「渡された失効集合」に化け、`{checked: true,
  // revoked: false }`＝**失効確認をしていないのに「確認済み・失効なし」**と報告する
  // （本関数の JSDoc が明示的に避けている状態そのもの）。`trustAnchors` も同様に、汚染値が
  // Trust Anchor 集合になると攻撃者 CA が信頼の起点になる。
  const revokedSerials = ownProperty<ReadonlySet<string>>(options, 'revokedSerials');
  const trustAnchors = ownProperty<VerifyRpAccessOptions['trustAnchors']>(
    options,
    'trustAnchors',
  ) as VerifyRpAccessOptions['trustAnchors'];
  // `intermediatesDer` も同じ own 限定読みに揃える。
  // 鎖読みだと、中間 CA を**渡していない**正当な呼び出しに `Object.prototype.intermediatesDer`
  // の汚染値が「渡された中間 CA 集合」として注入される。最終判定は Trust Anchor が握るため
  // 信頼バイパスそのものではないが、セキュリティ判定関数における fail-open 読みであり、
  // 兄弟実装 `etsi-tsl/etsi-tsl.ts` の `verifyQualifiedCertificate` は既に own 化済みである。
  const intermediatesDer = ownProperty<readonly Uint8Array[]>(options, 'intermediatesDer');
  const parsed = tryParse(options.certDer);
  if (parsed === undefined) {
    return invalidResult(options.requestedClaims, now, ErrorCodes.RP_ACCESS_CERT_SIG_INVALID);
  }
  const rp: RpDescriptor = { ...parsed.identity };
  const crossBorderWarning = isCrossBorder(rp.country);
  const errors: string[] = [];
  if (crossBorderWarning) {
    errors.push(ErrorCodes.RP_CROSS_BORDER_WARNING);
  }

  // (3) 有効期間。
  // `now` が NaN だと比較が常に false になり期限切れ証明書を通すため、`!(nb <= now <= na)` で fail-closed。
  if (!(now >= parsed.base.notBefore && now <= parsed.base.notAfter)) {
    errors.push(ErrorCodes.RP_ACCESS_CERT_OUT_OF_VALIDITY);
    return {
      valid: false,
      rp,
      claimAuthorization: denyAll(
        options.requestedClaims,
        ErrorCodes.RP_ACCESS_CERT_OUT_OF_VALIDITY,
      ),
      trustChain: [],
      revocation: revocationStatus(revokedSerials, parsed.serialHex, now),
      crossBorderWarning,
      errors,
    };
  }

  // (2) チェーン検証（granted な QTSP Trust Anchor へ）。
  const anchorsDer = grantedTrustAnchors(trustAnchors);
  const chain = await verifyCertificateChain(options.certDer, intermediatesDer ?? [], {
    trustAnchorsDer: anchorsDer,
    now,
  });
  // (4) 失効（Trusted List Status）。RP 証明書のシリアルが失効集合にあれば revoked。
  // 失効集合が渡されない場合は `checked: false`（未確認）であり、失効なしとは主張しない。
  const revocation = revocationStatus(revokedSerials, parsed.serialHex, now);
  const revoked = revocation.revoked;
  if (!chain.trusted) {
    errors.push(ErrorCodes.RP_ACCESS_CERT_SIG_INVALID);
  }
  if (revoked) {
    errors.push(ErrorCodes.RP_ACCESS_CERT_REVOKED);
  }

  // (5)-(7) 権限マッチング。
  const claimAuthorization = authorizeClaims(options.requestedClaims, parsed.scope);
  collectScopeErrors(claimAuthorization, errors);

  const issuerName = chain.trusted ? anchorLegalName(chain.anchorSubjectDer, trustAnchors) : '';
  const trustChain = chain.trusted ? [buildChainNode(parsed, issuerName)] : [];
  const valid = chain.trusted && !revoked && allClaimsAuthorized(claimAuthorization);
  return {
    valid,
    rp,
    claimAuthorization,
    trustChain,
    revocation,
    crossBorderWarning,
    ...(errors.length > 0 ? { errors } : {}),
    ...(chain.notAfter === undefined ? {} : { validUntil: chain.notAfter }),
  };
}

/** パースを試み、失敗時 undefined を返す（例外を外へ出さない）。 */
function tryParse(der: Uint8Array): ReturnType<typeof parseRpAccessCertificate> | undefined {
  try {
    return parseRpAccessCertificate(der);
  } catch {
    return undefined;
  }
}

/** スコープ違反 / purpose 違反の error コードを重複なく errors に集約する。 */
function collectScopeErrors(results: readonly ClaimAuthorization[], errors: string[]): void {
  for (const r of results) {
    // `reason` は拒否時だけ生やすキー。鎖読みすると汚染値が許可結果にも error として混入する。
    const reason = ownProperty<string>(r, 'reason');
    if (reason !== undefined && !errors.includes(reason)) {
      errors.push(reason);
    }
  }
}

/** 到達した RP 証明書と発行 Anchor 名から trustChain ノードを組み立てる（source は ETSI TSL 固定）。 */
function buildChainNode(
  parsed: ReturnType<typeof parseRpAccessCertificate>,
  issuerName: string,
): TrustChainNode {
  return {
    subject: parsed.identity.legalName || parsed.identity.legalId || parsed.serialHex,
    issuer: issuerName,
    validFrom: toIso(parsed.base.notBefore),
    validUntil: toIso(parsed.base.notAfter),
    source: 'etsi-tsl',
  };
}

/** 到達した Trust Anchor（subject DN 一致）の legalName を取り出す。特定できなければ空文字。 */
function anchorLegalName(
  anchorSubjectDer: Uint8Array | undefined,
  anchors: readonly QtspServiceCertificate[],
): string {
  if (anchorSubjectDer === undefined) {
    return '';
  }
  for (const a of anchors) {
    const parsed = tryParse(a.certDer);
    if (parsed !== undefined && derEquals(parsed.base.subjectDer, anchorSubjectDer)) {
      return parsed.identity.legalName || parsed.identity.legalId;
    }
  }
  return '';
}

/** パース不能時などの `valid:false` 結果を作る。 */
function invalidResult(
  requested: readonly RequestedClaim[],
  now: number,
  errorCode: string,
): RpAccessVerificationResult {
  return {
    valid: false,
    rp: { legalName: '', legalId: '', country: '', origin: '' },
    claimAuthorization: denyAll(requested, errorCode),
    trustChain: [],
    revocation: { checked: false, revoked: false, method: 'none', checkedAt: toIso(now) },
    crossBorderWarning: true,
    errors: [errorCode],
  };
}
