/**
 * trust/x509 のうち**ディレクトリ外から使われる面**だけを束ねるエントリ。
 *
 * X.509 v3 拡張まわりの読み取りは submodule に分かれているが、`trust/x509/` の外にいる
 * 消費者が必要とするのは次の 2 経路だけである。
 *
 * - `trust/rp-access/cert.ts`: RP Access Certificate の `origin`（URI SAN）と
 *   SubjectDirectoryAttributes を読むための拡張走査。
 * - `wallet/issuer-trust/x5c.ts`: `x5c` の leaf から Issuer の `iss`（URI SAN）と JWS 検証鍵を取る。
 *
 * CA 制約・名前制約・チェーン述語（`ca-constraints` / `name-constraints` / `name-matching` /
 * `critical` / `path-constraints`）は `trust/x509/` 内と `etsi-tsl/`（`x509.ts` / `chain.ts`）
 * からしか使われないので、ここからは再エクスポートしない。使う側がいない公開面を置くと、
 * 「どこから読まれているか」を調べないと変更の影響範囲が決まらなくなる。**ディレクトリ内の
 * import は従来どおり具体ファイルを直接指す**（入口を二重に持たないため）。
 */

export {
  type CertificateExtensions,
  certificateExtensions,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_DIR_ATTRS,
  subjectAltNameUris,
  subjectAltNameUrisOfCertificate,
} from './san.js';
export { spkiToPublicKeyJwk } from './spki-jwk.js';
