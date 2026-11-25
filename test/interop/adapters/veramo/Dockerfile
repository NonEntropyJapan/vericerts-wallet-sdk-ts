# test/interop/adapters/veramo/Dockerfile
#
# Veramo（実 npm パッケージ、モックなし）を相互運用テスト harness の統一ピア契約で公開する。
# ベースイメージはダイジェスト固定（タグは再 push で中身が変わり、nightly / Release Gate の結果が
# 再現できなくなる。更新は `docker buildx imagetools inspect` で新ダイジェストを得る）。
FROM node:22-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

WORKDIR /app
# package-lock.json で解決版を固定する（`npm install` は build のたびに `^7` 系の最新を取得し、
# nightly の結果が日ごとに変わる）。依存更新は lockfile を再生成する手動 PR で行う。
COPY test/interop/adapters/veramo/package.json test/interop/adapters/veramo/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY test/interop/adapters/veramo/server.mjs test/interop/adapters/veramo/agent.mjs test/interop/adapters/veramo/issue-jwt.mjs ./

ENV PORT=8091
EXPOSE 8091
CMD ["node", "server.mjs"]
