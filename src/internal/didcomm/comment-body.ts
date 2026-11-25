import { ownProperty } from '../prototype-safety/own-property.js';

/**
 * 任意の `comment` を DIDComm メッセージ body へ写す。`comment` は **own 限定**で読む。
 *
 * 省略した `comment` が `Object.prototype.comment` の汚染値を拾うと、相手へ送る
 * `offer-credential` / `request-presentation` 等の body に攻撃者の文言が混入する。
 *
 * @param options `comment` を持ち得るオプション。
 * @returns `comment` を own で持つときだけ `{ comment }`、それ以外は空オブジェクト。
 */
export function commentBody(options: { readonly comment?: string }): { comment?: string } {
  const comment = ownProperty<string>(options, 'comment');
  return comment !== undefined ? { comment } : {};
}
