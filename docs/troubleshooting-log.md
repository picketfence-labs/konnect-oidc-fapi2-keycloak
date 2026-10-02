# 障害対応記録

予期しない動作、失敗した操作、原因、対処、再確認事項を記録します。認証情報や token の実値は記載しません。

## 2026-10-02: `gh pr edit`がProjects classic互換エラーで失敗した

- 期待: WP2のDraft PR本文へCI成功結果を追記する。
- 実際: `gh pr edit --body-file`のGraphQL queryが`pullRequest.projectCards`で拒否された。PRのcodeとCIは成功済み。
- 対処: 同じ本文をJSON fileの`body`へ格納し、`gh api repos/<owner>/<repo>/pulls/<number> --method PATCH --input <file>`で更新した。
- 再確認: REST APIの本文更新は成功。merge、Issue close、runtime変更は行っていない。

## 2026-10-02: WP2検証のprovider取得がsandbox内で失敗した

- 期待: 隔離worktreeの`make validate`が静的検証を完了する。
- 実際: `terraform init`が`registry.terraform.io`のDNS/network制限で失敗し、後続の検証へ到達しなかった。
- 対処: provider取得と静的検証だけを許可する実行で再試行した。Terraform apply、Docker起動、Konnect変更は行っていない。
- 再確認: `make validate`はTerraform、静的チェック、JWK export、runtime secret renderingを含め成功した。実TLS/token受入試験は未実施で、別の隔離環境previewに記録する。

## 2026-10-02: API foundationのCA作成が既存CAとの一意制約で拒否された

- 期待: 承認済みpreviewのAPI create3／third-party create4、update/delete=0を適用し、両post-sync diff=0になる。
- 実際: API Certificate 2件は作成されたが、CA `77777777-7777-4777-8777-777777777777`はHTTP409 `unique-certificate-per-entity`。API残差はCA create1。third-partyの4件は独立に成功し、post-sync diff=0、ID・タグ・公開証明書・Vault参照・global plugin設定の一致を確認した。
- 原因: API CPの既存v1 CA `33333333-3333-4333-8333-333333333333`と同じ公開証明書を異なるIDで登録しようとした。同じCP内でのCA証明書一意制約をread-only decK diffは検出しなかった。既存CAの公開DERとrole入力は一致、tagsは`[fapi2-demo]`だった。
- 保全確認: sync前後の両CP既存Service／Route／Plugin／Certificate／CAのIDとcanonical hashが不変。APIの成功した2 Certificateもremoteで照合。CA再試行、既存CA変更、削除によるrollbackは行わなかった。Docker、realm、runtimeは未操作。
- 対処案: [ADR 0014](decisions/0014-reuse-existing-api-ca.md)。API foundationから重複CA宣言を外し、固定ID・タグ・公開DER一致をdecK起動前にread-onlyで確認する。既存CAへfoundationタグを足さず、WP3 runtimeで既存ID・タグを維持する。
- 再確認: 修正PRのlocal/CI検証、利用者merge後のmainでCA前提照合と両live diff=0を確認する。現mainのAPI diffはCA create1のままであり、WP1完全受入と後続WP開始は保留。

## 2026-10-02: 新規Control Planeの空schema一覧が不完全応答として拒否された

- 期待: schemaがまだ登録されていない新規Control Planeで、HTTP 200の空一覧を0件として扱い、承認済みのschema同期を継続できる。
- 実際: 一覧APIがJSON literal `{}` を返し、`request_schema_pages`は`items`と`page`がないため拒否した。対象schemaの個別GETは404だった。
- 原因: Konnect SDKの`ListPluginSchemas`モデルでは`items`と`page`、および`page.total_count`がoptionalであり、空一覧で応答全体が空objectになるケースがある。
- 対処: HTTP 200の最初のpageでcursor未設定、かつ応答がliteral `{}` の場合だけ、`items: []`とterminal `page.total_count: 0`へ正規化する。次pageの空object、部分応答、null items、pagination不整合、重複やcursor停滞は引き続き拒否し、全inventory検証前に書き込みを行わない。
- 仕様根拠: [Kong SDKのListPluginSchemas Go model](https://raw.githubusercontent.com/Kong/sdk-konnect-go/main/models/components/listpluginschemas.go)は`Items`と`Page`を`omitempty`として定義し、[対応するSDK model documentation](https://github.com/Kong/sdk-konnect-go/blob/main/docs/models/components/listpluginschemas.md)も両フィールドをoptionalとしている。空objectを空一覧として扱う判断は、この型定義と新規CPの実応答からの判断である。
- 検証時の補足: 一時的なapply後確認scriptがAPI Control Plane名を既定値へ固定していたためpostcheckが一度失敗した。scriptを設定値参照に直してpostcheckを再実行し成功した。Terraform applyは再実行していない。本体WP1のControl Plane名照合には不具合はなかった。

## 2026-10-02: stacked実装PRのmerge先がmainではなかった

- 期待: 設計PR #13をmainへmerge後、WP1実装PR #14もmainへ反映する。
- 実際: #13はmain `1b34c5c`へmergeされたが、#14はbaseの`docs/third-party-luna-handoff`へmergeされた（`3dc5268`）。mainに実装は入っていなかった。
- 対処: 新branch `feat/wp1-main-delivery`でWP1実装commitだけを最新mainへ載せ直し、main反映用PRを提出する。コードはレビュー済みhead `101e2aa`と同一。merge済み設計の差分は重複させない。
- 再確認: 載せ直した直後のtreeが`101e2aa`と一致し、local test/pluginと差分空白検査が成功。追加変更はこの記録だけ。main merge後の独立再検証とlive基盤受入は、反映用PRのmerge後に行う。

## 2026-10-02: 設計PR #5のCIがjob setupで停止した

- 期待: PRの既存image workflowがtest/build/scanへ進む。
- 実際: run `36960974289`はjob setupで失敗し、test/buildは実行されなかった。
- 原因: annotationは`aquasecurity/trivy-action@0.33.1`を解決できないと報告。公式tagは`v0.33.1`で、SHAは`b6643a29fecd7f34b3597bc6acb0a98b03d33ff8`。workflowは設計PRの変更対象外。
- 対処: WP1 #7へ参照修復と独立validate/test checkを引き継ぐ。CI成功とは扱わない。
- 再確認: ローカル`make validate`と`make test`は成功。修復後のGitHub Actionsとimage build/scanは未実施。

## 2026-10-02: SHA pin修復後もTrivy本体のinstallが失敗した

- 実際: PR #14の初回CIでvalidate、両imageのbuild/unit testは成功したが、Trivy setupがexit 1。scan自体は未実施。Actionの既定binary `v0.65.0`の公式release checksum URLも404だった。
- 調査: [固定Action source](https://github.com/aquasecurity/trivy-action/blob/b6643a29fecd7f34b3597bc6acb0a98b03d33ff8/action.yaml)で既定versionを確認。[公式事後報告](https://github.com/aquasecurity/trivy/discussions/10462)は旧GitHub releasesの削除を記録する。ActionはSHA pinのまま維持する。
- 対処: binary versionを[公式immutable release v0.74.0](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)へ固定。公式checksum assetのHTTP成功を確認。CRITICAL/HIGH、ignore-unfixedとexit-code 1を維持し、scanを省略しない。
- 再確認: 修正commitでGitHub Actionsを再実行して判定する。image公開と環境適用は未実施。

## 2026-10-02: image scanが既存baseとJWT依存の脆弱性で失敗した

- 実際: PR #14のrun `36984064367`はbuild/unit/SBOMまで成功し、scanで失敗。Kongはsystem OpenSSLと`/usr/bin/pebble`、PoP verifierはPyJWT 2.10.1とpipのvendored packageを検出した。scanのseverityと失敗判定は維持する。
- 対処: PyJWTを[公式2.14.0](https://github.com/jpadilla/pyjwt/releases/tag/2.14.0)へ固定し、builderからruntime依存だけをコピーしてpip/ensurepip等をruntimeから除去。PS256、issuer/audience/scope/cnf検査に加え、unknown critical header、JWKS redirect、unknown-kid refresh制限と鍵rotation復旧の回帰検査を追加した。
- Kong: 3.16.0.0の公式multi-platform digest `sha256:e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4`を固定し、UbuntuのOpenSSL packageだけを更新する。公式amd64 imageのdigest検証済みlayerを読み取り調査したところ、PebbleはUbuntu base layerに存在し、entrypoint、Kong CLI、shell/Lua計2,313ファイルに参照なし。entrypointはOpenRestyを直接実行するため、当imageでは未使用と判断してPebbleを除去する。Pebbleがprocess supervisorであることは[公式資料](https://ubuntu.com/docs/pebble/explanation/security/)で確認した。これは調査からの判断であり、AS runtimeの動作証明ではない。
- 再確認: 更新依存のPoP回帰検査とlocal静的検査が成功。CIへnetwork noneの`kong prepare`とNGINX設定検査を追加し、build/test/SBOM/scanを修正commitで再実行する。live DP起動・接続・worker可視性はWP5で未実施。
- CI追記: run `36985754948`のPoP test起動が`PYTHONPATH=/app`でimageの依存pathを上書きし、`jwt` importに失敗。test起動のpathへ`/opt/python-deps`も含めて再実行する。validate workflowは成功し、Kong jobはmatrixのfail-fastでcancelされたため未判定。

## 2026-10-02: foundation templateをsemantic YAML validatorで読めなかった

- 期待: foundationのtemplate値を安全なdummyへ置換し、YAML構造・重複key・entity ID・tag・秘密参照・transport configを検査する。
- 実際: template式をエスケープしたquoteで記述した初期版は、decKのGo templateとして不正な二重quoteを含んでいた。行単位の文字列検査ではentity構造と重複keyも検出できなかった。
- 対処: decKが受理するtemplate形式へ直し、PyYAMLの重複key拒否loaderでparseする。placeholderにenv変数名を保持し、証明書とkeyのID対応も比較する。
- 再確認: `make validate`の`deck file validate`と意味検証、`make test`のpositive/negative fixtureが成功。

## 2026-10-02: worker環境変数の宣言が単一env directiveになっていた

- 実際: `KONG_NGINX_MAIN_ENV`へ複数変数を空白で並べた初期宣言は、各変数のworker引継宣言になっていなかった。
- 対処: [Kongのtemplate](https://github.com/Kong/kong/blob/master/kong/templates/nginx.lua)のdirective挿入と[NGINXのenv構文](https://nginx.org/en/docs/ngx_core_module.html#env)に従い、固定の`env` directiveを変数ごとに分ける。これら公開sourceからの静的判断であり、exact Kong 3.16.0.0の実worker可視性はWP5の未実施項目。
- 再確認: 両DPの必要変数集合と、1 directiveあたり1変数の構文を静的testで照合し、`make validate`/`make test`が成功。

## 2026-10-02: PR #5のmergeが自動承認レビューに拒否された

- 期待: 利用者の「PRの確認とマージ」指示に従い、レビュー済み設計PRをmergeする。
- 実際: merge実行前にautomatic approval reviewが拒否した。mainは更新されていない。
- 理由: リポジトリの「人間のレビュー担当者に代わってPull Requestをmergeしない」規則を優先する判定。
- 対処: PR #5に限った規則の例外承認を利用者へ確認。迂回せず、設計/受入整理は固定headを基準に継続する。
- 再確認: 利用者がPR #5限定の例外を明示承認し、2026-10-02にmerge成功。main commitは`bc4a063`。設計merge待ちは解消した。

## 2026-10-02: 旧gh CLIのPR編集がProject APIで失敗した

- 実際: `gh pr edit 13 --base main`が廃止されたProjects classicの`projectCards`照会で失敗した。
- 対処: REST APIの`PATCH /repos/{owner}/{repo}/pulls/13`でbaseだけをmainへ変更した。
- 再確認: API応答でbase=mainを確認。PRのmergeは行っていない。

## 2026-10-02: Terraform provider schemaのread-only取得がsandboxで失敗した

- 期待: インストール済みproviderから`terraform providers schema -json`で型を確認する。
- 実際: sandbox内では4 providerがplugin protocol handshakeで失敗した。
- 対処: 同じschema照会だけを権限昇格して再実行し、成功した。state値や秘密値は表示せず、CPのcomputed endpointとDP certificateのrequired fieldを確認した。
- 再確認: HCL変更、plan/apply、resource更新は実施していない。schema取得成功をlive環境のplan成功として扱わない。

## 2026-10-02: 公開SDK照会がGitHub OAuthのSAML制約で拒否された

- 実際: Kong公式SDKの公開sourceを`gh api`で読む操作がorganization SAML enforcementにより403となった。
- 対処: 認証なしの公開API/sourceから、custom schemaの一覧・個別取得の応答型だけを確認した。非公開情報やSAML保護された情報は取得していない。
- 再確認: 一覧の`items[].lua_schema`と個別取得の`fields`を区別し、schema drift確認を全page一覧取得へ修正した。live Konnectのschema照会／更新は行っていない。

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
