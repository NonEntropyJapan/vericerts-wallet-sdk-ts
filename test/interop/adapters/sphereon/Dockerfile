# test/interop/adapters/sphereon/Dockerfile
#
# Sphereon SSI-SDK（実 npm パッケージ、モックなし）を相互運用テスト harness のネイティブ
# VC-API 契約で公開する。`npm ci`（package-lock.json でツリーを固定。`overrides` による
# ky-universal 依存・git+ssh 依存の回避）を使う点が bun 製の他アダプタと異なる。
# ベースイメージはダイジェスト固定（タグは再 push で中身が変わり、nightly / Release Gate の結果が
# 再現できなくなる。更新は `docker buildx imagetools inspect` で新ダイジェストを得る）。
FROM node:22-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

WORKDIR /app
# git: 推移的依存の一部（@veramo-community/lds-ecdsa-secp256k1-recovery2020、package.json の
# overrides で git+https に固定済み）が npm install 中に git clone を必要とする。
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY test/interop/adapters/sphereon/package.json test/interop/adapters/sphereon/package-lock.json ./
RUN npm ci --omit=dev

COPY test/interop/fixtures ./test/interop/fixtures
COPY test/interop/adapters/sphereon/server.mjs ./test/interop/adapters/sphereon/server.mjs

ENV PORT=8096
EXPOSE 8096
CMD ["node", "test/interop/adapters/sphereon/server.mjs"]
