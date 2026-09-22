# 障害対応記録

予期しない動作、失敗した操作、原因、対処、再確認事項を記録します。認証情報や token の実値は記載しません。

## 2026-09-15: OIDC が作るヘッダーを基本 Route の条件にできない

- 期待: `X-Demo-Department` に応じて複数の Kong Route を選ぶ。
- 実際: Kong の基本ルーターは認証 plugin より先に動く。
- 対処: Route と Service を各 1 つにし、access フェーズの Route By Header で Upstream を選ぶ。ADR-0001 を参照。

## 2026-09-15: Auth0 の PAR は完全には宣言的に有効化できない

- 期待: Terraform がテナントと client の PAR を管理する。
- 実際: client の PAR 要求は設定できるが、テナント設定は Dashboard 操作が必要。
- 対処: PKCE を既定とし、PAR はテナント設定後の任意機能にする。

## 2026-09-16: Auth0 connection 作成に必要な scope が不足

- 期待: レビュー済みの Terraform plan がすべてのリソースを作る。
- 実際: 一部を作成した後、Management API の `create:connections` 不足で 403 になった。
- 対処: scope を追加し、残りのリソースの新しい plan を作って確認する。古い plan を再利用しない。

## 2026-09-16: ユーザー作成が connection の有効化より先に進んだ

- 実際: Terraform が接続の client 割り当てとユーザー作成を並列に進めたため、ユーザー作成が失敗した。
- 対処: 2 つの `auth0_user` に `depends_on = [auth0_connection_clients.demo]` を追加した。

## 2026-09-16: デモユーザーのログインが別の database connection を選んだ

- 実際: Auth0 は新しい regular web client にテナント既定の `Username-Password-Authentication` を自動で割り当てる。デモユーザーは別の接続にいるため、ログインは `Wrong email or password` になった。
- 注意: `auth0_connection` data source の `enabled_clients` は live API の一覧を過少に返した。これをそのまま書き戻すと、共用テナントの他アプリの割り当てが消える恐れがある。
- 対処: `GET /api/v2/connections/{id}/clients` で実際の割り当てを確認し、既存 client を維持して Gateway client だけ外す。管理開始前に既存 resource を Terraform へ import した。

## 2026-09-16: OIDC の token 交換が 401 になった

- 実際: callback で `supported token endpoint authentication method was not found` と記録された。`client_secret_post` と `client_secret_basic` の切り替えでは解決しなかった。
- 調査結果: Gateway 3.16 でも同じ症状が出た。後に OIDC plugin の client secret が空だと判明したため、3.15 の不具合が直接原因だったとは確定できない。
- 対処: Auth0 provider が client secret を読める Management API scope を用意し、Terraform refresh と decK 差分をレビューしてから同期する。

## 2026-09-16: data plane が OIDC 設定を拒否した

- 実際: data plane は healthy でもルートは 404 で、`ssl_verify` を無効にできないという cluster ログが出た。
- 対処: 両方の decK ファイルで `ssl_verify: true` を明示し、差分を確認して同期した。

## 2026-09-22: Gateway 3.16 の起動時に port 8000 が競合した

- 実際: 別の Docker project が port 8000 を使用していた。解放後も、このデモのコンテナーは network 接続を失った状態で healthy を返した。
- 対処: 両方の Compose env file を渡して Kong コンテナーだけを再作成した。Gateway と UI がそれぞれ port 8000 と 3000 で応答し、Konnect は data plane を互換状態と判定した。

## 2026-09-22: 3.16 でも callback が 401 になった

- 実際: OIDC plugin と Terraform output の client secret が空だった。
- 原因: Auth0 Management API token に `read:client_credentials` または `read:client_keys` がなかった。
- 対処: 利用者が Dashboard で scope を追加した。refresh-only plan と decK diff をレビューし、secret の実値を表示せず非空を確認して適用・同期した。続く callback では `jws algorithm (HS256) is disabled` が出たため、Auth0 client の ID token 署名を RS256 に設定した。ブラウザーログインが成功した。

## 2026-09-22: 成功したログイン後に UI が空に見えた

- 原因: httpbin の応答全体を表示し、長い bearer token と cookie が画面幅を押し広げていた。
- 対処: UI の表示をルーティング証跡だけに限定した。さらに Request Transformer で Upstream へ送る `Authorization` と `Cookie` を削除した。再リクエストでは両ヘッダーが httpbin に届かなかった。

## 2026-09-22: 偽装ヘッダーのテストが CORS で止まった

- 原因: localhost:3000 の preflight が `Accept` と `Content-Type` だけを許可していた。
- 対処: `X-Demo-Department` と `X-Demo-Route` を追加した。同期後、engineering の認証済みセッションで `sales/sales-route` を送っても、httpbin は `engineering/engineering-route` を受け取った。
