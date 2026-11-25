# Use the verified release tarball in an independent consumer. npm is supplied by the pinned install stage.
FROM node:22-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d AS install
WORKDIR /app
COPY package.json ./
COPY artifact ./artifact
COPY test/interop/install-live-artifact.mjs ./test/interop/install-live-artifact.mjs
RUN artifact="$(node test/interop/install-live-artifact.mjs)" && npm install --ignore-scripts --legacy-peer-deps --no-audit --no-fund --workspaces=false "$artifact"

FROM oven/bun:1-slim@sha256:1846adf22496bd711036aae8be147e57bdebbaea2e5264e3e0b5af1db187d9a4
WORKDIR /app
COPY --from=install /app/package.json ./package.json
COPY --from=install /app/node_modules ./node_modules
COPY artifact ./artifact
COPY test/interop ./test/interop
COPY scripts ./scripts

ENV PORT=8090
EXPOSE 8090
CMD ["bun", "--preload", "./scripts/packed-consumer/preload-bun.mjs", "test/interop/adapters/vericerts/server.mjs"]
