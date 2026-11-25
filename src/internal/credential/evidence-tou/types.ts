/**
 * W3C VC `evidence` / `termsOfUse` の生データ型。
 *
 * `VerifiableCredential`（vc.ts）の `evidence` / `termsOfUse` フィールドが参照する。ODRL Policy の
 * 最小サブセット（permission / prohibition / obligation + constraint）を表現する。
 */

/**
 * W3C VC の `evidence` 単一エントリ（発行根拠）。
 *
 * `interpretEvidence` で UI 表示や LoA 判定に使う `EvidenceInterpretation` に正規化する。
 * W3C VC Data Model の evidence は拡張可能なため、既知フィールド以外も保持できるようにする。
 */
export interface EvidenceEntry {
  /** evidence エントリの ID（URI）。 */
  readonly id?: string;
  /** evidence の type（例: `["DocumentVerification"]`）。文字列単体も許容する。 */
  readonly type: string | readonly string[];
  /** 確認を実施した検証者の識別子。 */
  readonly verifier?: string;
  /** 参照した根拠ドキュメント種別（例: `DriversLicense`）。 */
  readonly evidenceDocument?: string;
  /** 被験者の立会い形態。 */
  readonly subjectPresence?: 'Physical' | 'Digital' | 'Remote';
  /** ドキュメントの提示形態。 */
  readonly documentPresence?: 'Physical' | 'Digital';
  /** 根拠文書のハッシュ値。 */
  readonly hashValue?: string;
  /** 追加の拡張プロパティ（未知フィールドを保持する）。 */
  readonly [key: string]: unknown;
}

/**
 * W3C VC の `termsOfUse` 単一エントリ（利用条件）。
 *
 * `prohibition` / `permission` / `obligation` を評価するための ODRL Policy の最小サブセット。
 */
export interface TermsOfUseEntry {
  /** ルール ID（違反時に `ToUViolation.ruleId` として返す）。 */
  readonly id?: string;
  /** termsOfUse の type（例: `IssuerPolicy` / `odrl:Set`）。 */
  readonly type?: string;
  /** 許可規則（ODRL permission）。 */
  readonly permission?: readonly OdrlRule[];
  /** 禁止規則（ODRL prohibition）。違反時は既定で `deny`。 */
  readonly prohibition?: readonly OdrlRule[];
  /** 義務規則（ODRL obligation）。未履行時は既定で `warn`。 */
  readonly obligation?: readonly OdrlRule[];
  /** 追加の拡張プロパティ。 */
  readonly [key: string]: unknown;
}

/**
 * ODRL 風のルール（permission / prohibition / obligation の各エントリ）。
 *
 * `action`（利用行為）に対し、`constraint` で用途・時間・地域の条件を表現する。
 */
export interface OdrlRule {
  /** ルールを一意に識別する ID（違反メッセージに使う）。 */
  readonly uid?: string;
  /** 対象アクション（例: `use` / `present` / `share`）。単体または配列。 */
  readonly action?: string | readonly string[];
  /** 対象アセット。 */
  readonly target?: string;
  /** 適用先の主体（Verifier 識別子等）。 */
  readonly assignee?: string;
  /** 制約条件（用途 / 時間 / 地域）。 */
  readonly constraint?: readonly OdrlConstraint[];
  /** 違反時の重大度上書き（既定は規則種別に依存）。 */
  readonly severity?: 'deny' | 'warn';
}

/**
 * `odrl.ts` の制約評価器が解釈できる比較演算子の語彙。
 *
 * 適用先は `leftOperand` の種別で分かれる:
 * - 文字列制約（`purpose` / `spatial`）: `eq` / `neq` / `isAnyOf` / `isPartOf` / `isNoneOf`
 * - 時刻制約（`dateTime`）: `lt` / `lteq` / `gt` / `gteq` / `eq` / `neq`
 *
 * ここに無い演算子、および対象外の組み合わせ（例: `purpose` に `lt`）は「制約を満たさない」
 * （不成立）として扱う。エラーにはしない（未知語彙を含む VC を受け取っても評価を継続するため）。
 */
export type OdrlOperator =
  | 'eq'
  | 'neq'
  | 'lt'
  | 'lteq'
  | 'gt'
  | 'gteq'
  | 'isAnyOf'
  | 'isPartOf'
  | 'isNoneOf';

/**
 * ODRL 制約（`leftOperand` operator `rightOperand`）。
 *
 * 例: `{ leftOperand: "dateTime", operator: "lteq", rightOperand: "2026-12-31T00:00:00Z" }`。
 */
export interface OdrlConstraint {
  /** 制約対象（`purpose` / `dateTime` / `spatial` 等）。 */
  readonly leftOperand: string;
  /**
   * 比較演算子。`OdrlOperator` が評価器のサポート語彙で、対応外の値は制約不成立として扱う。
   *
   * 受信した VC 本文の生データを表す型のため、`| (string & {})` を併用して任意の文字列も保持できる
   * ようにしている（未知演算子を含む VC のパースを壊さない）。ポリシー著述時は `OdrlOperator` の
   * 補完が効く。
   */
  readonly operator: OdrlOperator | (string & {});
  /** 比較値。単体または配列（`isAnyOf` / `isNoneOf` 用）。 */
  readonly rightOperand: string | readonly string[];
}

/**
 * 評価できない語彙に出会ったときの倒し方。
 *
 * - `fail-open`（既定）: 相互運用性を優先し、解釈できない語彙は判定に影響させない。
 * - `fail-closed`: 解釈できない語彙を「判定不能」として `deny` 違反にする。
 */
export type UnknownVocabularyPolicy = 'fail-open' | 'fail-closed';

/**
 * `checkTermsOfUse` / `validateTermsOfUseOnPresentation` の評価オプション。
 *
 * 既定はいずれも `fail-open` で、省略時の挙動は本オプション導入前と同一。fail-closed は opt-in。
 */
export interface ToUCheckOptions {
  /**
   * 評価できない制約（未知 `leftOperand` / 対応外 `operator` / 構造不正な constraint）の扱い。
   *
   * `fail-open`（既定）では未知 `leftOperand` は「制約を課さない」= 成立として扱われる。
   * `fail-closed` では規則種別に関わらず `deny` 違反を立てる。
   */
  readonly unknownConstraint?: UnknownVocabularyPolicy;
  /**
   * 評価対象外の `action`（`use` / `present` / `*` 以外）を持つルールの扱い。
   *
   * `fail-open`（既定）ではそのルールを無視する。`fail-closed` では `deny` 違反を立てる。
   */
  readonly unknownAction?: UnknownVocabularyPolicy;
}
