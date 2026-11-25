/**
 * W3C VC の evidence を解釈し、要求された保証レベル（LoA）を満たすか判定する。
 *
 * `interpretEvidence` は evidence エントリ（object | object[]）をパースし、type / trustLevel を
 * 正規化して `EvidenceInterpretation[]` を返す。`verifyEvidence` は解釈結果の最大 trustLevel が
 * 要求 LoA 以上かを判定する。いずれも純粋関数で、DID 解決・ネットワークを要さない（単体テスト可能）。
 *
 * セキュリティ: 例外 message / context に VC 本文（evidence の値）を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { isPlainObject as isRecord } from '../object-guards.js';
import type { VerifiableCredential } from '../vc/vc.js';
import type { EvidenceEntry } from './types.js';

/** Level of Assurance（保証レベル）。W3C evidence の trustLevel / EUDI LoA に対応する。 */
export type LoA = 'low' | 'substantial' | 'high';

/** LoA の順序。充足判定（`>=`）に使う。 */
const LOA_RANK: Readonly<Record<LoA, number>> = Object.assign(
  Object.create(null) as Record<LoA, number>,
  { low: 0, substantial: 1, high: 2 },
);

/**
 * evidence の `type` 別に既定の trustLevel を推定するためのヒント。
 *
 * evidence 側で `trustLevel` / `assuranceLevel` を明示していない場合のフォールバックに使う。
 * 未知 type は最も保守的な `low` に倒す（fail-safe: 過大評価しない）。
 */
const TYPE_DEFAULT_LOA: Readonly<Record<string, LoA>> = Object.assign(
  Object.create(null) as Record<string, LoA>,
  {
    DocumentVerification: 'substantial',
    PhysicalDocumentVerification: 'high',
    KYCProof: 'substantial',
    ElectronicSignature: 'high',
  },
);

/** evidence の確認項目。 */
export interface EvidenceCheck {
  /** 確認種別（例: `document_authenticity`）。 */
  readonly type: string;
  /** 確認結果（`passed` / `failed` / `unknown`）。 */
  readonly result: 'passed' | 'failed' | 'unknown';
}

/** evidence を UI 表示・LoA 判定用に正規化した解釈結果。 */
export interface EvidenceInterpretation {
  /** evidence エントリの ID。 */
  readonly id?: string;
  /** 正規化済み type 配列（先頭が主種別）。 */
  readonly type: string[];
  /** 確認を実施した検証者。 */
  readonly verifier?: string;
  /** 参照した根拠ドキュメント種別。 */
  readonly evidenceDocument?: string;
  /** 被験者立会い形態。 */
  readonly subjectPresence?: 'Physical' | 'Digital' | 'Remote';
  /** ドキュメント提示形態。 */
  readonly documentPresence?: 'Physical' | 'Digital';
  /** 実施した確認項目。 */
  readonly checks: EvidenceCheck[];
  /** 根拠文書のハッシュ。 */
  readonly hashValue?: string;
  /** LoA 相当の信頼レベル。 */
  readonly trustLevel: LoA;
}

/** `verifyEvidence` の結果。 */
export interface EvidenceVerificationResult {
  /** 要求 LoA を満たすか。 */
  readonly sufficient: boolean;
  /** evidence の解釈結果一覧。 */
  readonly interpretations: EvidenceInterpretation[];
  /** 不充足時の理由（充足時は undefined）。 */
  readonly reason?: string;
}

/** `type`（string | string[]）を string[] に正規化する。空・不正は構造不正として拒否する。 */
function normalizeType(type: unknown): string[] {
  if (typeof type === 'string') {
    return type.length > 0 ? [type] : [];
  }
  if (Array.isArray(type)) {
    return type.filter(isNonEmptyString);
  }
  return [];
}

/**
 * LoA 文字列かを判定する。
 *
 * `evidence.ts` 内の trustLevel 解決に加え、`auth/request.ts` の `requiredLoA` パース（VC 選択後の
 * LoA 判定フックに渡す要求値の構造検証）でも同じ判定を再利用する。
 */
export function isLoA(value: unknown): value is LoA {
  return value === 'low' || value === 'substantial' || value === 'high';
}

/**
 * evidence エントリ 1 件から trustLevel を決定する。
 *
 * 優先順位: 明示の `trustLevel` / `assuranceLevel`（LoA 文字列）→ type 既定値 → `low`。
 * 未知 type や欠落時は保守的に `low` へ倒す（過大評価による fail-open を避ける）。
 */
function resolveTrustLevel(entry: EvidenceEntry, types: string[]): LoA {
  // evidence は VC 本文由来のデータであり、`entry.trustLevel` をプロトタイプ鎖で読むと、
  // LoA を**明示していない** evidence が汚染値で `high` に昇格し、`low` フォールバック
  // （fail-safe: 過大評価しない）を飛び越える。自身のプロパティに限って読む。
  const explicit =
    ownProperty<unknown>(entry, 'trustLevel') ?? ownProperty<unknown>(entry, 'assuranceLevel');
  if (isLoA(explicit)) {
    return explicit;
  }
  let best: LoA = 'low';
  for (const t of types) {
    const mapped = TYPE_DEFAULT_LOA[t];
    if (mapped !== undefined && LOA_RANK[mapped] > LOA_RANK[best]) {
      best = mapped;
    }
  }
  return best;
}

/** evidence の `checks` を正規化する（欠落・不正エントリは無視する）。 */
function normalizeChecks(raw: unknown): EvidenceCheck[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const checks: EvidenceCheck[] = [];
  for (const item of raw) {
    if (!isRecord(item) || typeof item.type !== 'string') {
      continue;
    }
    const result =
      item.result === 'passed' || item.result === 'failed' || item.result === 'unknown'
        ? item.result
        : 'unknown';
    checks.push({ type: item.type, result });
  }
  return checks;
}

/** VC の `evidence`（object | object[] | undefined）をエントリ配列へ正規化する。 */
function collectEntries(evidence: VerifiableCredential['evidence']): EvidenceEntry[] {
  if (evidence === undefined) {
    return [];
  }
  const list = Array.isArray(evidence) ? evidence : [evidence];
  return list.filter((e): e is EvidenceEntry => isRecord(e));
}

/**
 * VC の `evidence` プロパティをパース・構造検証し、UI 表示 / LoA 判定用に正規化する。
 *
 * `evidence` は W3C VC Data Model に従い object 単体・配列いずれも受理する。各エントリの `type` は
 * 必須（string | string[]、空は不正）。`type` を欠くエントリがあれば構造不正として `VC_SCHEMA_INVALID`
 * （3002）を送出する（部分的な黙殺は Verifier 判定を誤らせるため）。
 *
 * @throws object エントリのうち自身の `type` が空（欠落・空文字・空配列等）のものがある場合（VericertsError、code `3002`）。
 *         object でないエントリ（文字列・`null` 等）は例外にせず捨てる。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function interpretEvidence(
  vc: VerifiableCredential,
): Promise<EvidenceInterpretation[]> {
  // `vc.evidence` も VC 本文（データ）。プロトタイプ鎖で読むと、evidence を**持たない** VC に
  // 汚染された evidence 配列が生えて LoA 判定の材料になる。
  const entries = collectEntries(ownProperty<VerifiableCredential['evidence']>(vc, 'evidence'));
  const interpretations: EvidenceInterpretation[] = [];
  for (const entry of entries) {
    // evidence は VC 本文由来のデータ。フィールドをプロトタイプ鎖で読むと、`type` を持たない
    // 構造不正な evidence が汚染値で「type あり」に化けて 3002 のガードを素通りし、以降の
    // フィールドも汚染値で埋まる。自身のプロパティに限って読む。
    const types = normalizeType(ownProperty<unknown>(entry, 'type'));
    if (types.length === 0) {
      // type 欠落は構造不正。値（VC 本文）は message に載せない。
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    const id = ownProperty<unknown>(entry, 'id');
    const verifier = ownProperty<unknown>(entry, 'verifier');
    const evidenceDocument = ownProperty<unknown>(entry, 'evidenceDocument');
    const subjectPresence = ownProperty<EvidenceEntry['subjectPresence']>(entry, 'subjectPresence');
    const documentPresence = ownProperty<EvidenceEntry['documentPresence']>(
      entry,
      'documentPresence',
    );
    const hashValue = ownProperty<unknown>(entry, 'hashValue');
    const interpretation: EvidenceInterpretation = {
      ...(typeof id === 'string' ? { id } : {}),
      type: types,
      ...(typeof verifier === 'string' ? { verifier } : {}),
      ...(typeof evidenceDocument === 'string' ? { evidenceDocument } : {}),
      ...(subjectPresence !== undefined ? { subjectPresence } : {}),
      ...(documentPresence !== undefined ? { documentPresence } : {}),
      checks: normalizeChecks(ownProperty<unknown>(entry, 'checks')),
      ...(typeof hashValue === 'string' ? { hashValue } : {}),
      trustLevel: resolveTrustLevel(entry, types),
    };
    interpretations.push(interpretation);
  }
  return interpretations;
}

/**
 * Verifier が VC の `evidence` を評価し、要求 LoA を満たすかを判定する。
 *
 * `interpretEvidence` で解釈した各 evidence の最大 trustLevel が `requiredLoA` 以上なら
 * `sufficient=true`。`failed` の確認項目を含む evidence はその LoA を無効化する（fail-safe）。
 * evidence が 1 件も無い場合は `low` 要求のみ充足し、それ以上は不充足とする。
 *
 * @throws evidence の構造不正時（`interpretEvidence` が `VC_SCHEMA_INVALID` 3002 を送出）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function verifyEvidence(
  vc: VerifiableCredential,
  requiredLoA: LoA,
): Promise<EvidenceVerificationResult> {
  const interpretations = await interpretEvidence(vc);
  const required = LOA_RANK[requiredLoA];

  let best = -1;
  for (const it of interpretations) {
    // failed の確認を含む evidence は保証レベルとして採用しない。
    const hasFailure = it.checks.some((c) => c.result === 'failed');
    if (hasFailure) {
      continue;
    }
    best = Math.max(best, LOA_RANK[it.trustLevel]);
  }

  // evidence 無し（best === -1）は low 要求のみ充足。
  const effective = best === -1 ? LOA_RANK.low : best;
  const sufficient = effective >= required;
  return {
    sufficient,
    interpretations,
    ...(sufficient ? {} : { reason: `required LoA "${requiredLoA}" not met by provided evidence` }),
  };
}
