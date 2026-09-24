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

## 2026-09-23: decKのPEM環境変数展開でYAML parseに失敗した

- 期待: decKの環境変数テンプレートから生成済みPEMを読み込み、Gateway差分を表示する。
- 実際: 改行を含むPEMがYAML parse前にそのまま展開され、2行目以降が無効なYAMLになった。
- 対処: client certificateと秘密鍵はenvironment Vault referenceへ変更し、data plane runtimeだけに値を渡す。公開CAだけをJSON/YAML互換のescape済み文字列として展開する。実生成値を使った`docker compose config`と`deck file validate`で再確認した。

## 2026-09-23: Konnectにcustom plugin schemaがなくdecK diffが停止した

- 期待: file-based custom pluginを含む設定について、対象を絞ったdecK差分を取得する。
- 実際: 13件の作成差分を計算した後、Konnectが`no plugin-schema for 'fapi-client-auth-bridge'`を返した。
- 対処: Konnect要件に合わせて`schema.lua`をself-containedにし、登録状態のread-only checkと明示的なschema syncを別コマンドにした。schema未登録時は`deck-diff`と`deck-sync`を事前に停止する。

## 2026-09-24: Route BのOIDC pluginだけが部分syncで拒否された

- 期待: レビュー済みの14エンティティをKonnectへ同期する。
- 実際: 13エンティティは作成されたが、Route Bの`openid-connect`だけが`validation error: unknown field`で拒否された。
- 原因: RSA JWKのmodulusキー`n`を引用していなかったため、decKのYAML解釈で真偽値キーとして扱われ、Konnectへ未知フィールドとして渡された。
- 対処: JWKキーを`"n"`と明示的に引用した。`client_jwk`を段階的に復元するオンライン検証で`n`追加時だけ失敗することを確認し、修正後は秘密値を含まないダミー設定をKonnectのschema validation APIで検証した。
- 再確認: 送信範囲の承認後、残差分がRoute BのOIDC plugin作成1件だけであることを確認して再同期した。同期後の差分は作成0・更新0・削除0になった。

## 2026-09-24: Keycloakのrealm importファイルをmountできなかった

- 期待: `make up`で生成済みrealm JSONをKeycloakのimportディレクトリへread-only mountする。
- 実際: `/opt/keycloak/data`全体の永続化mountと、その配下へのrealmファイルmountが重なり、Docker Desktopがmountpointをrootfs外として拒否した。
- 対処: Keycloakの永続化対象を`/opt/keycloak/data/h2`へ絞り、`/opt/keycloak/data/import`へのrealmファイルmountと重ならないようにした。静的テストで重複mountの再導入を防止する。

## 2026-09-24: data planeがKonnectの公開CAを検証できなかった

- 期待: Kong data planeがKonnectへ接続して同期済みGateway設定を受信する。
- 実際: Kongはhealthyだったが両Routeが404になり、cluster/telemetry接続は`unable to get local issuer certificate`で停止した。
- 原因: `KONG_LUA_SSL_TRUSTED_CERTIFICATE`をローカル開発CAだけに設定し、コンテナーのsystem trust storeを置き換えていた。
- 対処: `system,/etc/kong/fapi/ca.crt`を指定し、Konnectの公開CAとローカルKeycloak CAを同時に信頼する。TLS検証は無効化しない。

## 2026-09-24: Route BのPARでJWKのkidが一致しなかった

- 期待: Route BのOIDC pluginがPS256のclient assertionを生成し、KeycloakのPAR endpointで認証される。
- 実際: Keycloakは`client_credentials_setup_required`を返し、設定済み公開鍵の`kid`とassertionの`kid`が一致しなかった。
- 原因: Kong側は固定値`route-b-pkj`を使っていたが、Keycloakは公開鍵SPKI DERのSHA-256 thumbprintを`kid`として生成する。
- 対処: JWK export時に同じSPKI thumbprintを算出し、runtime JWK、OIDC plugin、custom pluginへ`DECK_ROUTE_B_JWK_KID`として一貫して渡す。
- 再確認: Konnect同期後の差分が作成0・更新0・削除0であることを確認し、Kongを再作成した。Route AとRoute BはいずれもPARを完了してKeycloakの認可endpointへ302を返した。

## 2026-09-24: UIからRoute Aを選ぶと401になった

- 期待: Route AのPAR後にKeycloakのログイン画面が表示される。
- 実際: Keycloakから`Invalid redirect_uri`が返り、Kongのcallbackは認可codeがないため401を返した。
- 原因: FAPI 2.0 client policyを有効にしたclientへ、平文HTTPの`http://localhost:8000`をredirect URIとして登録していた。
- 対処: 両Routeのredirect URIとUIのGateway endpointを`https://localhost:8443`へ統一する。UIも`https://localhost:3443`で配信し、login・logout後のredirectとGateway CORS originをHTTPSへ揃える。Keycloakのpost-logout URIはwildcardを使わず、Routeごとの完全一致URIを登録する。UIはKeycloakをJavaScriptから直接呼ばないため、clientの不要な`webOrigins`を空にする。Kong proxyとUIには開発用CAで署名した専用server証明書を設定する。
- 再確認: decK同期後の差分は作成0・更新0・削除0になった。HTTP UIはHTTPS UIへ308を返し、HTTPS UIは200を返した。Route AとRoute BはPAR後、cookieを保持したbrowser相当のリクエストでKeycloakログイン画面へ200で到達した。

## 2026-09-24: ログイン後のtoken交換が401になった

- 期待: Keycloakのログイン後、Kongがauthorization codeをtokenへ交換する。
- 実際: Keycloakは`Offline tokens not allowed for the user or client`を返し、Kongはtoken endpointの400を401として返した。
- 原因: refresh tokenの取得に不要な`offline_access` scopeを両Routeで要求していた。Keycloakはこれを通常のrefresh tokenではなくoffline tokenの要求として扱った。
- 対処: OIDC scopeを`openid profile`へ絞る。Keycloak clientの`use.refresh.tokens=true`は維持し、通常のrefresh tokenを発行・revokeする。
- 再確認: decK同期後の差分は作成0・更新0・削除0になった。Route Aは生成済みデモユーザーによるログイン、authorization code交換、token取得、HTTPS UI復帰まで成功した。

## 2026-09-24: 認証後のUpstream呼び出しが502になった

- 期待: Kongがtokenにバインドしたclient証明書を提示し、PoP verifierが`/evidence`を返す。
- 実際: PoP verifierのTLSハンドシェイクがclient証明書を`certificate unknown`として拒否し、Kongは502を返した。server側を修正すると、同じ理由でKeycloak JWKS取得が失敗して401になった。
- 原因: 既存の開発CAに`keyUsage=keyCertSign`がなく、Python 3.13のstrict X.509検証が証明書chainを拒否した。標準のOpenSSL検証では同じchainが成功した。
- 対処: PoP verifierはclient証明書とJWKS取得の両方でCA・hostname検証を維持し、既存の開発CAに限ってstrict flagを外す。mTLSは`CERT_REQUIRED`のままにする。新規CAにはcriticalな`keyUsage=keyCertSign,cRLSign`を付ける。
- 再確認: Route Aを生成済みデモユーザーで実行し、token交換、KongからPoP verifierへのmTLS、JWT検証、証明書thumbprint照合が成功した。Gatewayは`binding_verified=true`を含むevidenceをHTTP 200で返した。

## 2026-09-24: 認証成功後もdepartmentとlogical_routeがnullになった

- 期待: Keycloakがデモユーザーの`department`と`route`をnamespaced claimへ追加し、Kongが同じ値をUpstreamヘッダーへ設定する。
- 実際: client protocol mapperは存在したが、両ユーザーのカスタム属性が空だったため、証跡の`department`と`logical_route`が`null`になった。属性を補正した後も、URI形式のclaim名に含まれるドットがJSON階層として解釈され、フラットなclaim参照は`null`のままだった。
- 原因: Keycloak 26はユーザープロファイルに未定義の属性を既定で無視する。realm import内の`department`、`departement`、`route`も保存されなかった。また、OIDC mapperのclaim名はドット記法をJSON階層として扱う。
- 対処: 3属性を管理対象にしたユーザープロファイルを宣言し、`make up`で既定プロファイルへマージしてから既存デモユーザーを冪等に同期する。Keycloak 26.7.4の管理APIは`unmanagedAttributePolicy`を含む更新を汎用parse errorで拒否したため、既定の無効設定を変更せず管理対象属性だけを追加する。URI claim名のドットはバックスラッシュでescapeし、同期処理で既存client mapperも補正する。PoP verifierとUIにはclaim値とKongが設定したヘッダー値を分けて表示し、一致結果も追加する。

## 2026-09-24: デモ前スナップショットで受入作業を保留した

- 完了済み: Route AとRoute Bのbrowser login、code exchange、Upstream mTLS、証明書束縛、`department`と`logical_route`のclaim、Kongが設定する`X-Demo-*`ヘッダーをlive環境で確認した。`make validate`と両RouteのE2E検証も成功した。
- 保留: Route AとRoute Bのrefresh token revoke、Kong session破棄、Keycloak SSO logout、反対Routeへの切り替えについて、wire-level証跡を自動取得する。
- 保留: `A-CERT-01`、`A-CERT-02`、`B-AUD-01`、`B-JTI-01`、`B-SPOOF-01`、`B-CERT-01`、`POP-01`、`POP-02`、`HEADER-01`、`LEAK-01`の異常系を自動化し、期待した境界で拒否されることを記録する。
- 保留: clean checkoutからの秘密情報生成、Keycloak起動、data plane接続、両Route実行を再現する。
- 保留: GitHub Actionsでテスト、SBOM生成、脆弱性スキャンを通し、KongとPoP verifierのimageをcommit SHA tagでGHCRへ発行してdigestを記録する。
- 再開時の順序: logoutとrevocation、異常系、clean checkout、GitHub ActionsとGHCRの順に進める。デモ環境の設定変更は、現在の動作確認済みスナップショットを保持してから行う。

## 2026-09-24: UIアクセスがnginxの`400 Request Header Or Cookie Too Large`になった(再発)

- 期待: `make destroy`と`make up`でコンテナーを再作成した後、`https://localhost:3443`のUIが表示される。
- 実際: `ui`コンテナー(`nginx:1.29-alpine`)が`400 Bad Request: Request Header Or Cookie Too Large`を返した。コンテナーを再作成しても再発した。
- 原因: UI・Kong・Keycloakを同一ドメイン`localhost`の別ポート(3443/8443/8444)で配信しているため、ブラウザーはポートを区別せずCookieを共有する。KeycloakのセッションCookie(`KEYCLOAK_SESSION`、`AUTH_SESSION_ID(_LEGACY)`、`KC_RESTART`等)が繰り返しのログイン試行やリアルム再importで積み重なり、Cookieヘッダー全体がUIのnginxのデフォルトヘッダーバッファを超えた。コンテナー再作成では解消しない、ブラウザー側に溜まった状態が原因のため。
- 対処: 即時回避としてブラウザーの`localhost`向けCookieを削除する。恒久対処として`ui/default.conf`へ`large_client_header_buffers 4 32k;`と`client_header_buffer_size 4k;`を追加し、多少のCookie肥大化を許容できるようにした。
- 再確認: 未実施。設定反映後、再度ブラウザーからUIへアクセスして200が返ることを確認する。以前と同じ事象が再発した場合は、UI・Kong・Keycloakのホスト名分離(同一`localhost`をやめる)を検討する。

## 2026-09-24: `make destroy`後の`make up`でログインボタンが`ERR_CONNECTION_REFUSED`になった

- 期待: `make destroy`の後に`make up`でコンテナーを再作成すれば、Route AとRoute Bのログインができる。
- 実際: UIでRoute AまたはRoute Bのログインボタンを押すと、どちらも`ERR_CONNECTION_REFUSED`になった。`docker compose ps`ではKongコンテナーだけが`Restarting`を繰り返していた。
- 原因: `make destroy`はTerraformが管理するKonnect control plane・data plane client証明書を含む全リソースを削除し、`infra/certs/tls.crt`・`tls.key`(data planeのクラスタ証明書、`infra/konnect.tf`の`local_file`)も削除される。一方`make up`は`generate-dev-assets`と`render-runtime`だけに依存し、Terraform applyを実行しない。そのため`destroy`後に`plan`/`apply`を挟まず`up`すると、Kongは`/etc/kong/certs/tls.crt`を読めず`cluster_cert: failed loading certificate`でクラッシュループし、8000/8443番ポートで待ち受けない。ブラウザーからはKongへの接続自体が存在しないため`ERR_CONNECTION_REFUSED`になる。UIやKeycloak自体は正常に起動していた。
- 対処: `make destroy`の後は、`make up`の前に必ずセットアップ手順を`plan`/`apply`からやり直す。

  ```bash
  make plan
  make apply
  make generate-dev-assets
  make plugin-schema-sync
  make deck-diff
  make deck-sync
  make up
  ```

  `apply`でKonnect control planeとdata plane証明書を再作成し、`generate-dev-assets`が新しい`infra/certs/tls.crt`・`tls.key`を`.generated/runtime.env`経由でKongへ渡す。`deck-sync`は新しいcontrol planeに対して14エンティティ全件を作成し直す(destroy前の登録内容は残らない)。
- 再確認: 上記手順を実行後、`docker compose ps`でKongが`healthy`になることを確認した。UIからRoute A/Bともにログイン画面まで到達可能になった。なお`apply`後に`.generated/demo-users.txt`のパスワードが再生成されるため、destroy前に控えたデモユーザーの資格情報は無効になる。
