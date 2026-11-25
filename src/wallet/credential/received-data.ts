/**
 * 生の VC を受領結果へ写す公開境界。構造の解釈と署名検証を別の API にし、
 * 解析だけの結果を検証済みとして保存しないよう判別子にも検証状態を残す。
 */
import { toReceivedCredential } from '../../internal/auth/oid4vci/facade/decode.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { verifyReceivedSdJwt } from '../issuer-trust/received-signature.js';
import type { ReceivedIssuerTrust } from '../issuer-trust/resolve.js';

/** 受領した VC の表示・保存に使う正規化データ。原本は `raw` のまま保持する。 */
export interface ReceivedCredentialData {
  readonly id?: string;
  readonly type: readonly string[];
  readonly issuer: string;
  readonly issuanceDate: string;
  readonly expirationDate?: string;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly raw: string;
  readonly format: 'jwt' | 'sd-jwt';
}

/** 構造と Disclosure の対応だけを読んだ結果。署名・有効期間は未検証。 */
export interface ParsedReceivedCredential extends ReceivedCredentialData {
  readonly verification: 'unverified';
}

/** SDK の発行者鍵解決・署名・時刻・Disclosure 検証を通った SD-JWT VC。 */
export interface VerifiedReceivedSdJwtCredential extends ReceivedCredentialData {
  readonly format: 'sd-jwt';
  readonly verification: 'verified';
}

/** SD-JWT VC 受領時の信頼材料と、要求した型の照合条件。 */
export interface VerifyReceivedSdJwtCredentialOptions {
  readonly issuerTrust: ReceivedIssuerTrust;
  /** 要求で選択した `vct`。指定時は署名対象の型と完全一致が必要。 */
  readonly expectedVct?: string;
}

/**
 * JWT-VC / SD-JWT VC の構造を正規化する。署名・有効期間を検証しない。
 * バックアップ再構築などのための解析であり、これだけで信頼評価や新規受領を許可しない。
 * @throws 構造・型・発行日時を解釈できない場合は `8020`。`iat` / `nbf` の既存要件も維持する。
 */
export function parseReceivedCredential(raw: string): ParsedReceivedCredential {
  const parsed = toReceivedCredential(raw);
  if (parsed.format !== 'jwt' && parsed.format !== 'sd-jwt') {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  return { ...parsed, format: parsed.format, verification: 'unverified' };
}

/**
 * SD-JWT VC を検証して正規化する。鍵解決は既存の x5c → 明示 opt-in の同 origin
 * HTTPS Metadata → DID の順を維持する。署名・時刻・Disclosure・期待 vct を全て SDK で検証する。
 * @throws 鍵解決不能は `3010/issuer_key_unresolved`、署名・vct 不一致は `3010`。
 * 期限切れ等の既存 `VericertsError` は元のコードを保つ。
 */
export async function verifyReceivedSdJwtCredential(
  raw: string,
  options: VerifyReceivedSdJwtCredentialOptions,
): Promise<VerifiedReceivedSdJwtCredential> {
  const trust = ownProperty<ReceivedIssuerTrust>(options, 'issuerTrust');
  if (trust === undefined || trust === null || typeof trust !== 'object') {
    throw new VericertsError(ErrorCodes.SIG_INVALID, {
      context: { reason: 'issuer_key_unresolved' },
    });
  }
  await verifyReceivedSdJwt(trust, raw, ownProperty<string>(options, 'expectedVct'));
  const parsed = parseReceivedCredential(raw);
  if (parsed.format !== 'sd-jwt') throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  return { ...parsed, format: 'sd-jwt', verification: 'verified' };
}
