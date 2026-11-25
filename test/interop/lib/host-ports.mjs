// test/interop/lib/host-ports.mjs
//
// compose のホストポートを run ごとに Docker へ割り当てさせ、ランナーが実際のポートを
// `docker compose port` で引くための共通処理。
//
// なぜ固定ポート（8090-8098）をやめたか: Release Gate の interop job は Nightly と同じ
// self-hosted ランナーで同時に走り得る。固定ポートのままだと後発の run が bind に失敗し、
// ピアの不調ではなく順番待ちでリリースが止まる。Nightly の `concurrency` を共有する案は、
// 待機が 1 件しか保持されずゲート側の run が cancel され得るため採らない。
// `docker-compose.yml` の `ports` はホスト側を空（`127.0.0.1::<コンテナポート>`）にしてあり、
// Docker が空きポートを選ぶ。選んでから bind するまでの競合が無いのが環境変数で渡す案との差。
//
// 解決に失敗したピアは `baseUrl` を持たず、`unresolved` に理由が残る（そのピアを使うペアは fail として
// 報告される）。`pairs.json` には戻り先になる固定 `baseUrl` を置いていない —— 古いポートへ黙って戻すと、
// 同じランナーで走る別 run のピアを叩いて pass し得るため。

import { fileURLToPath } from 'node:url';

const COMPOSE_FILE = fileURLToPath(new URL('../docker-compose.yml', import.meta.url));
/** ポート照会が応答しないまま matrix 全体が止まらないようにする上限。 */
const PORT_LOOKUP_TIMEOUT_MS = 30_000;

/**
 * `docker compose port <service> <containerPort>` の出力（`127.0.0.1:49154`）からポート番号を取る。
 * 進捗行が先に出ることがあるため最終行だけを見る。
 */
function parsePort(stdout) {
  const lines = String(stdout ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '');
  const port = /:(\d+)$/.exec(lines.at(-1) ?? '')?.[1];
  return port === undefined ? undefined : Number(port);
}

/**
 * ピア 1 件のホスト実ポートを引き、`baseUrl` を `http://localhost:<実ポート>` に差し替える。
 *
 * `service` / `containerPort` を持たないピア（compose ネットワーク内のアドレスを使う walt.id の
 * プロトコル層ピアや、解決経路を持たない `unavailable` なピア）はそのまま返す。
 *
 * @param {Function} spawnImpl `spawnSync` 互換（テストでは注入して差し替える）。
 * @param {object} peer `pairs.json` のピア定義。
 * @returns {object} `baseUrl` を実ポートで上書きしたピア、または `unresolved` 付きのピア。
 */
export function resolvePeerBaseUrl(spawnImpl, peer) {
  if (peer?.service === undefined || peer?.containerPort === undefined) return peer;
  const target = `${peer.service}:${peer.containerPort}`;
  const unresolved = (detail) => ({
    ...peer,
    baseUrl: undefined,
    unresolved: `host-port-unresolved: ${target} のホストポートを引けなかった（${detail}）`,
  });
  const proc = spawnImpl(
    'docker',
    ['compose', '-f', COMPOSE_FILE, 'port', peer.service, String(peer.containerPort)],
    { encoding: 'utf8', timeout: PORT_LOOKUP_TIMEOUT_MS },
  );
  if (proc?.error) return unresolved(`docker compose port の起動に失敗した: ${proc.error.message}`);
  if (proc?.status !== 0) {
    return unresolved(`exit ${proc?.status}: ${String(proc?.stderr ?? '').trim()}`);
  }
  const port = parsePort(proc.stdout);
  if (port === undefined) {
    return unresolved(`出力を解釈できなかった: ${JSON.stringify(proc.stdout)}`);
  }
  return { ...peer, baseUrl: `http://localhost:${port}` };
}

/**
 * ピアの配列（`uniformPeers` 等）またはオブジェクト（`didResolution.peers`）の `baseUrl` を
 * まとめてホストの実ポートで上書きする。入力は変更しない。
 */
export function resolvePeerBaseUrls(spawnImpl, peers) {
  if (Array.isArray(peers)) return peers.map((peer) => resolvePeerBaseUrl(spawnImpl, peer));
  return Object.fromEntries(
    Object.entries(peers ?? {}).map(([name, peer]) => [name, resolvePeerBaseUrl(spawnImpl, peer)]),
  );
}

/**
 * ピアへ HTTP を投げる直前に `baseUrl` を取り出す。解決できていないピアは理由付きで例外にする
 * （`pairs.json` の既定ポートへ黙って戻さないための最後の防波堤）。
 */
export function baseUrlOf(peer) {
  if (typeof peer?.unresolved === 'string') throw new Error(peer.unresolved);
  return peer?.baseUrl;
}
