# test/interop/waltid/tls/

相互運用テスト harness 専用の自己署名 TLS 証明書（**非秘匿・本番証明書ではない**）。

`server-cert.pem` / `server-key.pem`（`CN=issuer.waltid.interop.example`、SAN: `DNS:issuer.waltid.interop.example,DNS:verifier.waltid.interop.example,DNS:localhost,IP:127.0.0.1`）を
`test/interop/nginx/waltid-tls-proxy.conf` が TLS 終端に使う。`ca-cert.pem` / `ca-key.pem` は
その発行元の自己署名 CA。本 SDK の OID4VCI/OID4VP Holder クライアントが `credential_offer_uri` /
`response_uri` に要求する HTTPS を、walt.id の平文 HTTP イメージの手前で満たすためだけに存在する
（詳細は `waltid-tls-proxy.conf` のコメント参照）。

鍵種別は ECDSA P-256（`prime256v1`）を使う。Ed25519 で生成すると、`test/interop/run-waltid-protocol.mjs`
が Bun の `fetch({ tls: { ca } })` でこの CA を信頼させようとした際に
`UNKNOWN_CERTIFICATE_VERIFICATION_ERROR` になる（Bun 1.4.2 で確認済みの制約。curl や Node.js の
`NODE_EXTRA_CA_CERTS` では問題なく検証できるため、Bun 側の Ed25519 CA 証明書検証の制約と判断した）。

再生成する場合:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -x509 -key ca-key.pem -out ca-cert.pem -days 3650 -subj "/CN=vericerts-interop-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE"
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -key server-key.pem -out server.csr -subj "/CN=issuer.waltid.interop.example"
printf 'subjectAltName = DNS:issuer.waltid.interop.example,DNS:verifier.waltid.interop.example,DNS:localhost,IP:127.0.0.1\nbasicConstraints = CA:FALSE\n' > server-ext.cnf
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 3650 -extfile server-ext.cnf
rm -f server.csr server-ext.cnf ca-cert.srl
```

SAN の FQDN は SDK の公開ホスト検査（`isPublicHttpsUrl`）を通る名前で、walt.id の `baseUrl`・
`docker-compose.yml` の network alias・`nginx/waltid-tls-proxy.conf` の `server_name` と揃える
（`__tests__/waltid-public-host-config.test.mjs` が一致を検査する）。SAN に `localhost` /
`127.0.0.1` を残すのは、ホストからの生存確認（smoke）用。

`ca-cert.pem` を `test/interop/run-waltid-protocol.mjs` が `fetch` の `tls.ca` オプションへ
渡してこの CA を信頼する。
