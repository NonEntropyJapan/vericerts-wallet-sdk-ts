/**
 * HAIP SD-JWT VC 相互運用テストの対象実装（Peer）とロール定義。
 *
 * 各 Peer が担当できる役割と、ローカルの相互運用テストで検証する組み合わせを表現する。
 * 外部の実装との接続には、その実装を実行する環境が必要になる。
 *
 * ここで表す Peer は「役割カバレッジ」に基づく抽象であり、テストの期待ロール（Issuer / Holder /
 * Verifier）と、そのペアがマトリクス上でスコープ内かどうかを決定する。
 * VeriCerts 自身は各ロールを SD-JWT VC プリミティブで実装する。
 */

/** 相互運用テストの対象実装識別子。 */
export type PeerId = 'vericerts' | 'sphereon' | 'veramo' | 'waltid' | 'didkit' | 'eudi-rw' | 'ebsi';

/** 相互運用フローにおけるロール。 */
export type InteropRole = 'issuer' | 'holder' | 'verifier';

/** Peer の役割カバレッジ記述子。 */
export interface Peer {
  /** Peer 識別子。 */
  readonly id: PeerId;
  /** 表示名。 */
  readonly label: string;
  /** この Peer が担えるロール集合（マトリクスのスコープ判定に用いる）。 */
  readonly roles: ReadonlySet<InteropRole>;
}

/** ロール集合を簡潔に構築する。 */
function roles(...items: readonly InteropRole[]): ReadonlySet<InteropRole> {
  return new Set(items);
}

/**
 * 各実装が担当する役割を記録する Peer レジストリ。
 *
 * - vericerts: 全ロール（本 SDK は Issuer / Holder / Verifier を SD-JWT VC で実装する）。
 * - sphereon: Issuer / Verifier / Wallet(Holder)。
 * - veramo: Agent / Wallet(Holder) / Issuer。
 * - waltid: Issuer / Verifier。
 * - didkit: Issuer / Verifier。
 * - eudi-rw: Holder（定期 interop イベント参加）。
 * - ebsi: Trusted Registry / Resolver に加え、EBSI Conformance Testbed（CT）が
 *   OID4VCI Issuer として発行フローに参加する。SD-JWT VC の発行元となるため `issuer` を持つ
 *   （Verifier / Holder ロールはマトリクス上持たない）。
 */
export const PEERS: Readonly<Record<PeerId, Peer>> = {
  vericerts: { id: 'vericerts', label: 'VeriCerts', roles: roles('issuer', 'holder', 'verifier') },
  sphereon: { id: 'sphereon', label: 'Sphereon', roles: roles('issuer', 'holder', 'verifier') },
  veramo: { id: 'veramo', label: 'Veramo', roles: roles('issuer', 'holder') },
  waltid: { id: 'waltid', label: 'walt.id', roles: roles('issuer', 'verifier') },
  didkit: { id: 'didkit', label: 'DIDKit', roles: roles('issuer', 'verifier') },
  'eudi-rw': { id: 'eudi-rw', label: 'EUDI RW', roles: roles('holder') },
  // Conformance Testbed の Issuer を表す。Resolver 役はロール表現の対象外（DID 解決は別軸）。
  ebsi: { id: 'ebsi', label: 'EBSI', roles: roles('issuer') },
};

/** Peer がそのロールを担えるか（マトリクスのスコープ内か）を判定する。 */
export function supportsRole(peerId: PeerId, role: InteropRole): boolean {
  return PEERS[peerId].roles.has(role);
}

/**
 * `interop:<issuer>-issuer:<holder>-holder:<verifier>-verifier` 形式（ロール接尾辞付き）の 3 者マトリクス用
 * テスト名を組み立てる。ペア単位の結果レポートは `interop:<issuer>:<verifier>` を使う。
 *
 * 例: `interop:sphereon-issuer:vericerts-holder:waltid-verifier`。
 */
export function interopTestName(issuer: PeerId, holder: PeerId, verifier: PeerId): string {
  return `interop:${issuer}-issuer:${holder}-holder:${verifier}-verifier`;
}
