# 障害対応記録

予期しない動作、失敗した操作、原因、対処、再確認事項を記録します。認証情報や token の実値は記載しません。

## 2026-10-03: WP3 API応答scannerがPoP証明用thumbprintを誤検出した

- 期待: API応答のtoken、cookie、assertion、秘密鍵、証明書などはmemory内scanで拒否し、captureのPoP照合用thumbprintはreceiptへ保存せず比較できる。
- 実際: runtime未起動の独立synthetic再現で、typed introspectionの`cnf.x5t#S256`に含まれる公開証明書digestを、capture応答の同じdigestが`unknown` secretとして誤検出した。実tokenを使った漏えい、Gateway起動、OAuth/API runtime試験は発生していない。
- 原因: 応答scannerが全remember済み値を同じ機密候補として扱い、fixture leaf certificate由来の公開PoP binding digestを区別していなかった。
- 対処: hash-bound fresh Route A/B leaf certificateからdigestをmemory内で導出し、その2値だけを正確な`cnf.x5t#S256` fieldとして記録した場合にpublic fixture observationへ分類する。明示password/token等のsensitive category、未登録digest、未知scalar/listは引き続き検査対象。captureの完全digestはmemory内比較のみとし、receiptには既存のprefixだけを残す。
- 再確認: focused testで合法typed-introspection→capture経路を通し、同じdigestを明示secretとして記憶した場合、未知list、および未登録のcnf値はすべて拒否する。fresh fixtureの再準備後にruntime再試験が必要。

## 2026-10-03: WP3 candidate stateのdecK templateを補助YAML parserで直接読めなかった

- 期待: static testがAPI runtimeとfoundation entityの同一ID・タグ・証明書参照を構造で比較する。
- 実際: decK `${{ env "NAME" }}` expressionを展開前に通常YAML parserへ渡した補助testがparse errorになった。これはdecK正規経路の不正ではなかった。
- 対処: API candidateのtemplateはfoundationと同じbyte表記のまま維持し、static test内で既知env式を固定placeholderへ置換してから構造比較する。
- 再確認: `./scripts/deck.sh validate`と`tests/test_static.py`が成功。exact Gateway config acceptanceは別確認のまま。

## 2026-10-03: WP3 offline plugin schema probeの限界

- 期待: stock Kong 3.16.0.0からplugin schema fieldとhandler priorityを限定的に読む。
- 実際: 最初はplugin Lua/bytecode search pathが不足し、pluginを未loadと誤認した。KongのLua search pathを与えてread-only再試験したところ、OIDC/THM/pre-function schema・handler metadataが読み取れた。`tls-metadata-headers` schemaはloadしたがhandler module initializationは成功しなかった。
- 対処: 再試験のsanitized結果をGit外の`/private/tmp/wp3-schema-probe.lua`と`/private/tmp`配下receiptへ記録した。OIDCの`discovery` config候補をstateから除去し、TLS Metadata Headersの実priorityとTLS動作はstartup probeへ残した。
- 再確認: offline schema/priority結果はstartup、config acceptance、real TLS到達を証明しない。exact runtime acceptance前に`needs-design`を解除しない。

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

## 2026-10-03: WP2 harnessが初回PS256鍵をJWKSから見つけられなかった

- 期待: 隔離KeycloakでPS256 access tokenを発行し、発行者の公開鍵で署名とclaimsを検証した後、専用mTLS clientでintrospectionする。
- 実際: 初回の認可済みfixture runでは、token headerのkidに対応する鍵が事前取得済みJWKSに見つからず、RS-INT-AUD-02 Aをharnessが拒否した。sanitizedな事前JWKS概要にはRSA/RS256署名鍵とRSA-OAEP暗号化鍵があり、PS256署名鍵はなかった。修正後の2回目runではRS-INT-AUD-02 A/Bがともに成功し、`active=true`と必須claimを確認した。その後RS-INT-AUD-01 Aのmapper事前検査が停止した。Keycloakのlive mapperにはtemplateにない`userinfo.token.claim=false`があり、guardはPUT前に拒否した。他のoptional flowは未実行だった。
- 原因: Keycloak 26.7.4の[DefaultKeyManager](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/keys/DefaultKeyManager.java#L54-L78)は、要求されたuse/algorithmの有効鍵がない場合にfallback鍵の生成を試みるため、初回PS256署名鍵がdiscovery時のJWKS取得後に作られる場合がある。また、[AbstractOIDCProtocolMapper.getEffectiveModel](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/mappers/AbstractOIDCProtocolMapper.java#L159-L170)は`userinfo.token.claim`未設定時に`id.token.claim`の値を返す。audience mapperはID tokenを無効にしているため、live表現に`userinfo.token.claim=false`が追加された。
- 対処: tokenのkidが取得済みJWKSにない場合だけ、同じdiscovery `jwks_uri`をTLS検証・同一origin制約・redirect拒否のまま1回再取得する。再取得後も`kid`、RSA、署名用途、PS256が一致する公開鍵が一意でなければ拒否し、PyJWTによる署名・issuer・時間・audience・nonce検証を行う。token requestは再送しない。全Route mapperにKeycloakのeffective defaultsを明記し、attribute mapperの`userinfo.token.claim=true`とaudience mapperの`userinfo.token.claim=false`を宣言する。audience guardは他の差分を引き続き拒否する。初回・2回目のfixtureとsanitized receiptはGit外に保管し、次の確認は専用project/volumeのcleanup後に新しい`.generated/wp2-preview/`を生成して行う。
- 再確認: JWKS欠落/再取得とmapper既定値/strict driftの回帰testが成功した。2回目runのRS-INT-AUD-02 A/Bは実fixtureで成功した。その後のfresh attempt 04ではRS-INT-AUD-01とAS negativeを含む9結果すべて成功し、専用環境をcleanupした。[実試験履歴](design/third-party-wp2-runtime-evidence.md)へ初回の失敗も残す。

## 2026-10-03: B-AUD-01とB-CERT-01のclient-policy拒否が`invalid_grant`で返った

- 期待: 9ケースのfixture runでRS-INT-AUD-02 A/B、RS-INT-AUD-01 A/B、A-CERT-01/02、B-JTI-01を通過し、B-AUD-01とB-CERT-01も狙ったAS拒否として分類する。
- 実際: attempt 03では上記7ケースが成功した。B-AUD-01とB-CERT-01はともにHTTP 400 `invalid_grant`を返し、当時のハーネスが期待する外側error codeと異なるためfailになった。raw response bodyやerror descriptionは表示・保存していない。
- 原因: Keycloak 26.7.4の[AuthorizationCodeGrantType](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/grants/AuthorizationCodeGrantType.java#L177-L185)はcode、session、redirect URI、PKCE検査後にtoken-request client policyを実行し、`ClientPolicyException`を外側の`invalid_grant`へ包む。[SecureClientAuthenticationAssertionExecutor](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/executor/SecureClientAuthenticationAssertionExecutor.java#L112-L116)の誤ったassertion audience拒否と[HolderOfKeyEnforcerExecutor](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/executor/HolderOfKeyEnforcerExecutor.java#L96)の証明書欠落拒否は、内部で`invalid_request`を使うため、外側codeだけでは正常なgrant失敗と区別できない。
- 対処: HTTP 400かつerror codeが`invalid_grant`の場合だけ、response descriptionをmemory内でsourceの完全一致allowlistと比較し、`client_assertion_audience`または`mtls_client_certificate_missing`という固定enumへ変換する。raw descriptionは例外、stdout、receiptへ渡さない。B-AUD-01とB-CERT-01はHTTP status、code、enumの正確な組だけをpassにし、HTTP 401、generic `invalid_grant`、未知detail、誤ったenum、TLS失敗はfailのままにする。受入fixtureとREADMEに有効な事前positive controlsとこの分類規則を記録した。
- 再確認: 2つの既知detailとenum変換、wrong outer code、欠落・未知・相互に誤った理由・誤statusの拒否をunit testした。修正後のfresh attempt 04でB-AUD-01/B-CERT-01のHTTP 400・`invalid_grant`・対応する固定enumを実確認し、全9結果が成功した。attempt 03のfail receiptは保持する。独立`make validate`、`make test`（WP1 19件、WP2 26件）も成功。PR merge・main検証・利用者受入は別途必要である。


## 2026-10-03: WP4検証の初回実行でPython依存とprovider取得が止まった

- 期待: `make test`と`make validate`をWP4 worktreeで完了する。
- 実際: 初回`make test`はsystem `python3`にPyJWTがなく、`tests/test_pop_verifier.py`のimportで停止した。`make validate`も最初のTerraform initがsandbox内のregistry DNS制限でprovider一覧を取得できず、後続へ進まなかった。
- 原因: system Pythonと検証用Python環境が異なり、sandboxからregistry.terraform.ioへのnetwork accessもなかった。実装不具合や自動レビュー拒否ではない。
- 対処: 既存WP2 venvをPATH先頭にしてtestを再実行した。Terraform providerの取得・validateだけをnarrow escalationで再実行し、applyは行っていない。
- 再確認: `make test`はWP1 19件、WP2 26件、WP4 12件を含め成功し、`make validate`も成功した。UPSTREAM-01の実TLS試験は、別途previewを共有するまで起動していない。

## 2026-10-03: UPSTREAM-01のfresh TLS fixtureがclient側strict検証で止まった

- 期待: `127.0.0.1:19443`で専用API upstream identity、保護`/evidence`、peer pin拒否、client cert必須、credential非漏えいを確認し、sanitized receiptだけを残す。
- 実際: 初回sandbox内実行はloopback bindで停止した。承認済みのnarrow escalation後はTLS listenerを開始できたが、Python strict clientがfixture server証明書を検証コード85で拒否した。失敗receiptは上書きせず保持した。
- 原因: fresh CAにはSubject Key Identifierがあった一方、発行したleafにAuthority Key Identifierを付けていなかった。server側verify flagを緩めても、client側の既定strict検証には影響しない。
- 対処: fixture leafへCAのSubject Key Identifierから導くAuthority Key Identifierを追加し、CA chainとhostname検証を保った。no-client-cert試験は`ssl.SSLError`の`CERTIFICATE_REQUIRED`または`HANDSHAKE_FAILURE`だけを期待拒否とし、他のnetwork/TLS errorをpassにしない。receipt先の既存file・symlinkはTLS起動前に拒否し、各試験のreceiptはexclusive createする。
- 再確認: fresh attemptではhealthzとprotected `/evidence`が別々にHTTP 200となり、PyJWTの実PS256検証、Route Aの`cnf` binding、固定`azp` mappingを確認した。同一CA Route peerと同CN・別鍵peerは同一のvalid requestで401、証明書なしTLSは`TLSV13_ALERT_CERTIFICATE_REQUIRED`で拒否された。sentinel response/log漏えいなし、cleanup完了、port 19443解放を確認した。証跡は`.generated/evidence/wp4-upstream01-retry5.json`であり、fresh in-memory署名鍵によるfixture tokenを使った。Keycloak発行tokenやGateway統合の成功とは扱わない。

## 2026-10-03: WP3検証sandboxでprovider DNSとDocker socketが使えなかった

- 期待: `make validate`とfresh WP3 fixture preparationを完了する。preparationはprivate filesとread-only metadata checksだけを使い、runtimeを起動しない。
- 実際: 通常sandboxの最初の`make validate`はregistry.terraform.ioへのDNSで停止した。続くfixture preparationはDocker daemonへ接続できず停止し、runtimeは開始しなかった。
- 原因: 通常sandboxではprovider registryのnetwork accessとDocker socket accessが無効だった。どちらも構成検証の失敗を示す結果ではない。
- 対処: Terraform provider初期化・validationと、既存pinned image/projectのread-only確認を個別の狭い権限で再実行した。`apply`、`sync`、container startは行っていない。
- 再確認: `make validate`は成功した。read-only Docker metadataとquiet Compose検査後にfresh private WP3 assetsとsanitized preparation receiptを作成し、`.generated/wp3-preview/`はmode `0700`、receiptとasset filesは`0600`である。containerは起動しておらず、API runtime matrixは別のreview gateに残る。

## 2026-10-03: WP3 runtime preflightがdecKのrender済みplugin配置を誤認した

- 期待: 隔離API GatewayとKeycloakの試験前に、hash-bound API runtime stateが正確なService、HTTPS Route、4つのstock plugin、TLS upstream contractを保持することを確認する。
- 実際: 試験runnerは`validate_runtime_state_contract`で停止し、最初の失敗phaseがreceiptの最終化で`runtime_complete`に上書きされていた。失敗receipt `wp3-runtime-receipt-1791000171490065000.json`ではAPI response数が0で、API要求・OAuth flowは始まっていない。起動時log scanは実行できたが、これを全runtimeの`LEAK-01`成功とは扱わない。
- 原因: decK 1.53.1のrender出力はtop-level `plugins`を使わず、4つのAPI pluginを`services[0].routes[0].plugins`へ正規化する。validatorはtop-levelだけを調べていた。また、単一の失敗phaseを残す制御と、API通信前のlog scanを`LEAK-01`の全runtime証跡から区別する制御が不足していた。
- 対処: validatorを、単一のAPI Serviceとその唯一のHTTPS Routeにネストされた正確な4 pluginに限定した。余分なService、top-level/service-level plugin、競合するRoute/Service/consumer参照を拒否する。fixture preflightの各境界を固定phaseとして記録し、失敗時は最初の失敗phaseを保持する。API responseが0件ならclean startup-only scanは`LEAK-01 not_run`として記録する。
- 再確認: decK正規化形状、余分なServiceと競合scopeの拒否、正確なpreflight phase保持、API通信なしの`LEAK-01 not_run`を回帰testした。新しいfixtureのruntime再試験は未実施であり、前回のreceiptは変更していない。

## 2026-10-03: WP3 exact-image Admin schema probeにHTTP clientがなかった

- 期待: isolated Kongのloopback-only Admin APIからloaded plugin/schema metadataを取得し、schemaとpriorityを値を漏らさず記録する。
- 実際: matrix attempt `1791001794707077000`はstate contractの18項目を通過した後、exact imageに`curl`がなくschema probe前に停止した。metadata-only observation `1791002226505121000`もAdmin listener isolation後のroot GET clientがなく、schema/priority dataを返せなかった。どちらもOAuth/API requestは0件で、全runtimeの`LEAK-01`結果ではない。
- 原因: `kong/kong-gateway:3.16.0.0` fixture imageには`curl`と`wget`がなく、以前のprobeが存在しない実行ファイルを呼んでいた。read-only exact-image確認では`/usr/local/openresty/bin/resty`と`resty.http`が利用可能だった。
- 対処: host側runnerが`resty.http`のstreaming `body_reader`を使い、固定loopback Admin URLへGETだけを行う bounded clientを追加した。2xx以外、redirect、1 MiBを超えるbody、未知pathを拒否し、raw bodyはchild pipeからhost memoryへ渡すだけで表示・保存しない。固定stage/reason enumだけをdiagnostic receiptに記録する。cleanupはcontainer撤去とprivate asset削除後の期待port-free判定だけをbounded pollingし、pre-start port guardは変更しない。
- 再確認: focused testsでbounded request、client不在、redirect/oversize拒否、safe diagnostic shape、cleanup pollingの成功・timeout・他エラーを検証した。後続metadata-only observation `1791003913548008000`でexact-image `resty.http` GETと`connect(host, port)`が動作し、root/plugin/schema responsesを取得した。ここで初めて、schema field parserの別問題が判明した。

## 2026-10-03: WP3 metadata-only schema probeがnested `issuer`を重複と数えた

- 期待: exact Kong 3.16.0.0 loaded plugin versions/prioritiesとrequired plugin-schema field metadataを、限定された情報だけで記録する。
- 実際: observation `1791003913548008000`でGateway version `3.16.0.0`、stock plugin version `3.16.0`、priority `pre-function=1000000` / `openid-connect=1050` / `tls-handshake-modifier=997` / `tls-metadata-headers=996`が確認され、全plugin schema GETも成功した。OIDC schemaの`issuer` field countは3となったためschema probeを完了扱いにせず停止した。OAuth/API requestは0、cleanupはexit 0。
- 原因: generic recursive scanが、異なるnested record内の`issuer` nameをroot `config.issuer`と同じfield scopeとして数えていた。
- 対処: schemaのtop-level `fields`から唯一の`config` recordを要求し、その直接`fields`だけでwanted namesを数える。root config recordの重複/型不一致、同じdirect scopeの重複wanted field、malformed descriptorはfail closedとする。nested unrelated namesはcountしない。raw schema responseは保存・表示しない。
- 再確認: nested foreign `issuer`を無視しdirect duplicateを数えるhelper regression、duplicate issuerをrejectするprobe-level regression、single malformed descriptorをrejectするprobe-level regressionを追加した。WP3 flow 65 tests、full `make test`、narrow registry accessでの`make validate`、`git diff --check`が成功した。次のfresh metadata-only probeでこのexact Kong schema shapeを再確認する。full runtime matrixはまだ実行しておらず、これらの結果はAPI/LEAK-01 acceptanceではない。

## 2026-10-03: WP3 Admin schema field scanがnested issuer名を重複と数えた

- 期待: exact Kong 3.16.0.0 Admin APIのloaded plugin versions/prioritiesとrequired schema field metadataを、限定した値だけで記録する。
- 実際: metadata-only observation `1791003913548008000`でGateway `3.16.0.0`、stock plugin version `3.16.0`、priority `pre-function=1000000` / `openid-connect=1050` / `tls-handshake-modifier=997` / `tls-metadata-headers=996`を確認し、期待値と一致した。全plugin schema GETも成功したが、OIDC `issuer` field countが3となりprobeはschema全体の受入前に停止した。OAuth/API requestは0件、cleanupは成功した。
- 原因: field matcherがschema JSONを再帰走査し、別recordのnested `issuer` namesをroot OIDC `config.issuer`と同等に数えていた。
- 対処: matcherを唯一のtop-level `config` recordの直接`fields`だけに限定し、そのconfig recordが欠落/重複/異型なら全required fieldを未確定として失敗させる。同一direct scopeのduplicateとmalformed descriptorも拒否する。enumとtypeは従来どおりallowlist/shapeで制限し、raw schemaを記録しない。
- 再確認: nested unrelated `issuer`を無視すること、direct `issuer` duplicateを検出すること、single malformed descriptorをrejectすることをrunner-level regressionで検証した。最新65件のWP3 flow testsはpass。exact-imageでのdirect `config.fields`結果は次のfresh metadata-only observationで確認し、そのpass後だけfull matrixへ進む。今回の停止はschema parser診断で、実token/API失敗やLEAK-01 passとは扱わない。

## 2026-10-03: WP3 schema確認後のflow/cleanup実行はreceiptなしで終了した

- 期待: exact Kong metadata/schema probeがpassしたfresh fixtureで、続けてfull WP3 matrixを動かし、success/failureいずれもsanitized runtime receiptを残してからowned projectとfixtureをcleanupする。
- 実際: metadata-only observation `1791004932981995000`でGateway `3.16.0.0`、stock plugin priorities `1000000/1050/997/996`、required direct `config.fields`とTHM `REQUEST` enumを確認した。そのfresh fixtureに対するflow CLIとcleanup CLIはともにexit 1で、正式runtime receiptは作成されなかった。rootが専用project、volume、ports、private fixtureの除去を独立確認した。正式receiptがないため、OAuth/API requestの有無と停止phaseは不明であり、未取得として扱う。
- 原因確認: 実際のflow失敗原因はこの試行だけでは判定できない。実schema payloadを使ったoffline `main()` orchestrationでは、schema pass後にTLS SNI phaseで意図的に止めてもstrict runtime receiptが作成され、validatorを通った。syntheticな誤phase試験は実payloadの失敗原因を示すものではない。静的producer/validator照合で、header capture failure phase `upstream_capture_evidence`とlog scan phase `whole_runtime_log_scan`がcase/executionの固定enumに欠ける経路を見つけた。これは再現性のあるreceipt境界不備として修正したが、直前の実試行の原因とは断定しない。
- 対処: case recorderは有限phase集合を先に検査し、negative group失敗で元のmatrix group phaseを保持する。ログscan match/例外とupstream capture失敗を含むoffline full-main回帰をstrict writerへ通す。失敗時のstderr markerは`WP3_RUNTIME_FAILURE phase=<fixed phase> reason=<negative_matrix_failed|probe_failed>`、receipt拒否時は`WP3_RUNTIME_RECEIPT_FAILURE phase=<fixed phase> reason=<evidence_directory_unsafe|schema_rejected|destination_exists|write_failed>`だけとし、raw exceptionを表示せずreceipt/PASSの代用にしない。cleanupはdangling receipt symlinkを拒否してowned fixtureを除去し、port release timeoutもfixed statusとして記録する。
- Port確認: plain bindだけではclose後のTIME_WAITをactive listenerと誤認することがある。guardは指定portのprocess-owned TCP descriptorsをread-only確認し、SO_REUSEADDR bindでTIME_WAIT-onlyを確認する。active listenerとbound ownerは拒否し、lsof不明またはbind permissionでfreeを証明できない場合はfail closedとする。
- 再確認: phase、strict receipt、log scan、cleanupのfocused regression 10件がpassし、権限付きloopback-only OS試験でもactive listener/bound owner拒否とTIME_WAIT-only許容を確認した。full `make test`はWP3 flow 74件を含め成功（sandboxではloopback OS test 1件skip、そのtestは権限付き個別実行でpass）。`make validate`も成功した。これらの修正後にruntimeを再起動しておらず、full WP3、negative/TLS、LEAK-01受入は未実証。

## 2026-10-03: WP3 full isolated runtimeでweak-cipher、1001-header、LEAK-01の未解決が残った

- 期待: frozen WP3 sourceとfresh fixtureで、exact Kong 3.16.0.0 metadata、実Keycloak tokenによるA/B、negative/API/TLS境界、upstream mTLS、全lifecycle漏えいscanを検証する。
- 実際: immutable strict receipt `.generated/evidence/wp3-runtime-receipt-1791006905251048000.json`はoverall/full acceptance `fail`、28 rows中25 pass / 2 fail / 1 needs-design。Gateway `3.16.0.0`とrequired schema fields、plugin priorities `1000000/1050/997/996`を確認した。Route A/B positive、dedicated mTLS introspection、query/body/cookie token拒否、genuine missing API audience/scope拒否、same-token active true→false→true、PoP-01/02/03、ERR-01、caller-header sanitation、header 1000件431、TLS 1.1、SAN mismatch、untrusted CAはpassした。
- 未解決transport境界: 1001-header requestはHTTP 400でGateway policyより前に拒否されたため、ADR 0015のGateway 431を証明せず`needs_design`とした。TLS weak-cipherではclient-side MemoryBIOが対象cipherをClientHelloに含め、negative後のvalid controlもpassしたが、peer alertは`protocol_version`で、cipher-suite拒否理由として認められずfail。現在のreceiptはこのpeer rejectionがcipher policy起因と証明しない。
- 漏えいscan: whole-lifecycle container log scanは184/184 candidate valuesを調べ完了したが、9 secret matches（cookie 2、OAuth token 3、unknown 4）とcredential patterns `oauth_token_field` / `jwt_shape`がありLEAK-01 fail。public fixture/protocol observationsは別集計であり、上記9件から除外していない。20 API responses、19,928 bytesのresponse scanはsecret/pattern match 0。raw logsは保存していないため、該当ログのcontainer/service/stageとfield発生元は未特定で、実値もreceiptにない。これを誤検出と扱ったりcategoryから除外したりしない。
- 対処/状態: 観測値はsanitized receiptに保持し、rootがdedicated project、volume、private fixture、portsのcleanupを独立確認した。normal Compose/realm/Control Plane/Terraform変更は行っていない。弱cipherのserver-side protocol/cipher policyと、matchを識別しつつraw line/valueを記録しないservice別diagnosticをofflineで調査する。次のruntimeは新しい具体previewとreview後に限る。

## 2026-10-03: WP3のログmatch出所診断とTLS/header判定条件を準備

- 期待: 保存済みのLEAK-01 failを弱めず、次の承認済み隔離runで既存matchのservice別情報を安全に得る。TLS/headerの前段拒否をLua/plugin成功と混同しない。
- 実際: runtime receipt `1791006905251048000`を変更せず、追加runtime scanは行っていない。`keycloak`、`kong-api`、`pop-verifier`固定inventoryからstdout/stderrをmemory-onlyで読むper-service scanner、service別category/countを含むstrict receipt schema、subprocess/partial/oversize/timed-out negative testsを用意した。scanは各service/全体で4 MiB、全体60秒以内とし、partial/unknown/overflowはfail closed。raw log、credential値、match行は保存しない。global候補とsecret/pattern pass条件は維持する。
- 設計整理: [ADR 0016](decisions/0016-api-gateway-inbound-tls-policy.md)はAPI inbound modern/TLS 1.3-only方針と、effective policy・negotiated AEAD・TLS 1.2 offerのprotocol-layer rejectionに必要な証拠を定義する。[ADR 0015](decisions/0015-api-resource-server-header-boundary.md)はHTTP parserの1001-header HTTP 400をLua 431と分離し、exact parser provenance、well-formed wire count、under-limit positive、unchanged Upstream counter、sentinel/response check、negative後positive controlがそろわなければ受け入れない。
- 制約: これらは実装とunit evidenceであり、前回の9 secret matchesのservice/stage/cause、新しいTLS negotiation、1001 parser provenanceを立証しない。次回runtimeは新しいpreviewとreview後に限り、旧receiptの結果を遡及変更しない。

## 2026-10-03: WP3再実行でservice別match数とTLS/header transport結果を取得

- 期待: schema/priority確認後にfull matrixを実行し、全container logをscanしてTLS policyと1001-header拒否層を分類する。以前のreceiptは保持する。
- 実際: fresh runtime receipt `.generated/evidence/wp3-runtime-receipt-1791011336629777000.json`はstrict validatorを通過し、29 rows中25 pass / 1 fail / 3 needs-designを記録した。Gateway/schema priorities、fresh Keycloak発行Route A/B、dedicated mTLS introspection、audience/scope/active/PoP/ERR、header 1000件の431、TLS 1.1/SAN/CA拒否と9件のupstream captureはpassした。
- TLS: TLS 1.2-only strong-suite controlとweak-suiteで、exact TLS 1.2 ClientHello offer、`protocol_version` peer alert、negative前後のTLS 1.3 AEAD handshake、Upstream counter不変を確認した。Admin `ssl_cipher_suite=modern`は見えたが`ssl_protocols`は空で、effective allowed protocolsを証明できないため両variantはneeds-design。weak-suiteの結果をcipher-specific rejectionと説明しない。
- Header: 1001件のwell-formed wire requestはHTTP 400でGatewayより前に拒否された。exact wire count、pinned NGINX parser default 1000、under-limit positive controls、response scan、Upstream counter不変は確認した。一方、NOTICE levelのbounded log scanでは`client sent too many header lines` markerと対象API request pathのmarker deltaがどちらも0だった。HTTP 400をparser provenanceのpassへ引き上げずneeds-designを維持する。log levelやGateway policyは変更していない。
- LEAK-01: lifecycle log scanは186/186候補を確認し、cookie 2 / OAuth token 3 / unknown 4の9 secret matchesと`oauth_token_field` / `jwt_shape` patternsを検出した。service別ではKeycloakがcookie 1 / unknown 4、Kong APIがcookie 1 / OAuth token 3、verifierが0 matches / 0 bytes。Keycloakのpattern matchは0、Kong APIは両patternを持つ。API response scanは21件 / 21,913 bytesでsecret/pattern match 0。9 captureのpeer pin、header、CNF、caller sentinel checksはpassした。
- 制約: raw logsとmatch valuesはcleanupで破棄し、receiptにも保存していない。service別categoryは分かったが、Keycloakのcookie/unknown候補やKongのcookie/token matchの正確なcandidate keypathとlog contextは未特定。これらを誤検出と分類せずLEAK-01 failを維持する。rootは専用project、volume、private fixture、portsのcleanupを独立確認した。前のreceipt `1791006905251048000`を変更しない。
- 次の診断: runnerにcandidate category/callsite/field enumsとcounts、matching log line上のOAuth endpoint/query context enum/countを追加した。line contextは候補値とpath文字列の共起観測で、loggerや漏えい原因の証明ではない。まだ実runtimeでは未検証で、既存candidate/pattern scan、fail判定、bounded limitsを変更していない。header-limit INFO markerを観測するためWP3専用ComposeだけKong log levelを`info`へ上げる。通常Composeの`notice`、DEBUG禁止、ログ抑制なしは維持する。これは新しい未実行fixture差分で、現receiptを変更しない。次のruntimeは新しい具体previewとreview後に限る。

## 2026-10-03: inbound TLS metadata helper が Admin GUI の追加includeを拒否

- 期待: effective TLS metadata probeは、pinned Kong imageの`nginx -T`出力からAPI HTTP TLS listenerに適用されるprotocolを、Adminの要求値と分けてbounded metadataへ変換する。
- 実際: GUIを既定で有効にしたpublic-generated config probeは、成功診断と既知4ファイルに加えてGUI用の別include markerを含み、strict parserは`not_proven`として拒否した。これはoffline/public-generated構成の観測で、WP3 runtime受入ではない。
- 修正: helperは未知marker/includeを許容しないまま維持する。隔離WP3 Composeだけ`KONG_ADMIN_GUI_LISTEN=off`を明示し、Admin APIは既存どおりcontainer loopbackへ限定する。rootのoffline再確認では4 markerのみ、HTTP側の`ssl_protocols TLSv1.3`とexact API `listen 0.0.0.0:8443 ssl`が解析され、TLS 1.2へ改変したpolicyは拒否された。18 pure testsは別途レビュー済み。HTTP/API server scopeの`ssl_conf_command`も有効TLS overrideの可能性があるためparserがfail closedする。
- 制約: このoffline checkは実fixtureでの再実行ではない。GUI-offを含むfresh preparation receipt、source binding、TLS handshake controlsがそろうまで過去receiptのTLS needs-designを維持する。通常ComposeのAdmin/GUI設定は変更しない。


## 2026-10-03: isolated INFO fixtureでTLS/header provenanceとLEAK再検証

- 実際: fresh strict receipt `.generated/evidence/wp3-runtime-receipt-1791014398144929000.json`は29 rows中28 pass / 1 fail / 0 needs-design。API listenerのeffective TLS 1.3 policyはpinned config dump/image/versionへbindして確認し、TLS 1.2 strong/weak negative controlsもpassした。1001件目はwell-formed HTTP 400、NGINX parser marker/API request marker deltaが各1、999件controlとUpstream不変を確認した。
- LEAK-01: 190/190候補を確認し、cookie 2 / OAuth token 3 / unknown 5の10 secret matchesと`oauth_token_field` / `jwt_shape`を記録してfailを維持する。Keycloakは17,113 bytesでsession_state cookie 1とunknown 5（form submission other 1、introspection other 2、sid 1、sub 1）、Kong APIは26,757 bytesでcookie 1 / OAuth token 3、verifierは0。candidate matchをdemoteせず、raw logs/valuesは保持していない。context countsはsame-line co-occurrenceでloggerや漏えい原因の証明ではない。
- API response scan: 21件 / 21,917 bytesでsecret/pattern matchなし。専用project、volume、private fixture、portsのcleanupをrootが独立確認した。従前receipt `1791011336629777000`等は変更しない。
- 次の調査候補: query-token requestがOIDC前に拒否されるkey-only guardと、Keycloakの既知field labelsを使った診断を検討する。現時点で実装・runtime実証しておらず、10 matchを誤検知と扱わない。


## 2026-10-03: bounded LEAK candidate classification before exact runtime verification (historical)

- Actual: immutable receipt wp3-runtime-receipt-1791017200869688000.json has 36 acceptance rows pass and LEAK-01 fail. The scan checked 199/199 candidates and recorded cookie 1 / OAuth token 1 / unknown 5 matches, with 0 credential patterns. The API response scan checked 29 responses / 26,070 bytes and found no secret or pattern matches. Raw logs, tokens, cookies, and identifier values were not retained.
- Observation: Keycloak candidates included token-response session_state, introspection azp/jti/sid/sub, and a form field-name observation; Kong API had one api_query candidate. These labels and same-line context counts are diagnostics, not proof of emitter or cause. The candidate does not establish that a CookieJar value is an authentication cookie.
- Change: a bounded memory-only pending response collection now defers only exact top-level fields. A token-response session_state is reclassified only after the same response access token passes existing PS256 and claim verification and its signed sid matches exactly; azp must match the grant client. Authenticated successful introspection with active=true can reclassify exact top-level azp/jti/sid/sub only after existing same-token introspection checks and exact claim equality. Collection and token binding must match. Unresolved, mismatch, inactive, malformed, or overflow candidates retain their original cookie/unknown category. Credential collisions and pattern checks remain fail-closed.
- Other fixed classifications: only the exact two harmless API query targets and structural form field name username are fixed protocol constants. Query extras, encoded variants, credentials, form values, passwords, and unknown names remain sensitive. API response scans continue to evaluate all candidate categories strictly.
- Evidence: Keycloak 26.7.4 source links include AccessTokenResponse, IDToken, JsonWebToken, and AccessTokenIntrospectionProvider: https://github.com/keycloak/keycloak/blob/26.7.4/core/src/main/java/org/keycloak/representations/AccessTokenResponse.java ; https://github.com/keycloak/keycloak/blob/26.7.4/core/src/main/java/org/keycloak/representations/IDToken.java ; https://github.com/keycloak/keycloak/blob/26.7.4/core/src/main/java/org/keycloak/representations/JsonWebToken.java ; https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java . This source mapping does not prove authentication-cookie use or the exact log emitter.
- Verification status at that point: focused WP3 tests passed; full tests and exact runtime verification were pending. This historical entry is superseded by the final receipt below; its receipt and counts remain unchanged.

## 2026-10-03: final isolated WP3 runtime acceptance

- Actual: strict receipt `wp3-runtime-receipt-1791019160834567000.json` records 37/37 PASS, FAIL 0, needs-design 0. It scanned 194/194 log candidates; all three services had zero secret and credential-pattern matches. API response scan covered 29 responses and was clean. Final source freeze SHA was `16836905cc82d0d747f1f9ab7b083ba612bd09188572ca8cea00c614daa3b7b8`.
- Scope: fresh Keycloak-issued Route A/B tokens, introspection/audience/scope/active/PoP/ERR, query/header controls, TLS policy and negative controls, certificate forwarding and upstream mTLS passed. Root independently confirmed the isolated containers, volume, private fixture, and ports were cleaned. Earlier receipts, including the 36/37 LEAK-01 failure, remain immutable.
- Remaining gate: normal Control Plane migration was not applied. The latest read-only diff preview is 6 creates / 0 updates / 13 deletes and needs its separate human review/authorization before sync. WP5/WP6 have not started. No normal `make up`, realm update, or CP sync occurred.
- Verification: zero-skip `make test`, `make validate`, and `git diff --check` passed. The registry-dependent validation required network access; it performed no apply or sync.
