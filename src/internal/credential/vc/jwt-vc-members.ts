/**
 * JWT-VC の VC 本体を表現（`jwt-vc-body.ts`）に応じて構造検証し、envelope 突合に使う検査済みメンバを
 * 表現に依らない形で返す。
 *
 * `wrapped`（`vc` claim。日付は `issuanceDate` / `expirationDate`）と `flat`（payload が VC 本体。
 * 日付は `validFrom` / `validUntil`）で読む日付の名前だけが違い、突合の規則は同一である。検査済みの
 * own 値をそのまま返すので、呼び出し側は読み直さない（TOCTOU 回避。`vc-assert.ts`）。
 */

import {
  assertVerifiableCredentialMembers,
  assertVerifiableCredentialV2Members,
} from '../presentation/vc-assert.js';
import { jwtVcBodyOf } from './jwt-vc-body.js';

/** 表現に依らない、検査済みの VC 本体メンバ。 */
export interface JwtVcBodyMembers {
  /** 構造検証済みの VC 本体（`wrapped` なら `payload.vc`、`flat` なら payload 自体）。 */
  readonly vc: object;
  readonly issuer: string;
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  /** envelope の `nbf` と束縛する開始日時（`issuanceDate` / `validFrom`）。 */
  readonly startDate: string;
  /** envelope の `exp` と束縛する終了日時（`expirationDate` / `validUntil`。無ければ `undefined`）。 */
  readonly endDate: string | undefined;
}

/**
 * payload の VC 本体を構造検証し、検査済みメンバを返す。
 *
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function jwtVcBodyMembersOf(payload: Record<string, unknown>): JwtVcBodyMembers {
  const { form, body } = jwtVcBodyOf(payload);
  if (form === 'flat') {
    const checked = assertVerifiableCredentialV2Members(body);
    return {
      vc: checked.vc,
      issuer: checked.issuer,
      credentialSubject: checked.credentialSubject,
      startDate: checked.validFrom,
      endDate: checked.validUntil,
    };
  }
  const checked = assertVerifiableCredentialMembers(body);
  return {
    vc: checked.vc,
    issuer: checked.issuer,
    credentialSubject: checked.credentialSubject,
    startDate: checked.issuanceDate,
    endDate: checked.expirationDate,
  };
}
