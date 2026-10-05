# OIDC デモのセッション引き継ぎ

## 現在の作業状態（2026-10-04）

2026-10-05追記: 利用者が重い網羅検証の省略を承認した。代表外部redirect負例は通常Route Aでpass。metadata照合はrevocationだけ通知/public originと設定/internal originが不一致（Keycloak 26.7.4のfrontend builder仕様）。[ADR0021案](decisions/0021-wp5-revocation-metadata-gap.md)で現構成維持・既知差分受容を提案する。これは未承認で、META-02完全一致はpassにしない。

通常認可開始のclient key PEM読込500を発見し、restartでは回復しなかった。同じimage/config/PKIでTPのみforce-recreateするとCP再受領後に復旧。全worker gate、代表redirect、A/B login/API200/binding/signature/header/spoof/logoutがpassした。根本原因は断定せず、保存済みDPデータに関わる問題の可能性と回復手順を記録する。CPへのwrite・source変更・新image buildは実施していない。現在は監視付きでデモを再開済み。次の判断はmetadata差分の受容、次の実装packageはWP6。


main `f8c3a8f`（PR #23 merge後）で通常デモの統合確認が通った。利用者の具体的な承認を受け、API CPの旧A/B構成13件を削除し、Resource Server構成6件を追加した。共有CAとfoundation certificateは維持し、旧設定のprivate backupはGit外に保存している。third-party CPの追加11件、標準Keycloakの3 clientsとPS256 providerも反映済み。

通常A/Bとも、ログイン→API 200→期限後refresh→stock logoutが成功した。Route Aはtls_client_auth/sales、Route Bはprivate_key_jwt/engineering。API応答の署名検証・証明書binding・claimとheaderの一致がtrueで、偽装X-Demo headerも認証済みclaimへ上書きされた。UIのHTTPS応答は200。4 workerのreadiness確認後にだけ通常入口を開き、reloadでsupervisorが8443/3443を閉鎖し、UI/third-party DPを停止することも確認した。確認後は同じ構成を再起動し、監視付きでデモを再開した。

通常環境は、native arm64のKong 3.16.0.0 baseにmainのtransport/bridgeをread-only mountするprivate overrideを使う。API/verifierは既存公開amd64 imageを使う。これはソースと実フローの確認であり、published multi-architecture imageやclean checkout再現の受入ではない。通常APIのpost-sync diffはOIDC config.cache_tokens_saltの1 updateのみ（liveは非空、stateは未指定）。cache_tokensはfalseで、追加syncは行っていない。詳細は[障害対応記録](troubleshooting-log.md)を参照。

| WP / Issue | 現状 | 残件 |
|---|---|---|
| WP1 #7、WP2 #8、WP4 #10 | 受入済み・closed | なし |
| WP3 #9 | isolated 37/37と通常統合がpass | 利用者受入・close |
| WP5 #11 | AS直結・guard・通常A/B・supervisor・代表redirectがpass。網羅縮小承認済み | metadata revocation差分の受容判断と利用者受入・close |
| WP6 #12 | 未開始 | UI表示・reset/切替手順・clean checkout再現の仕上げ。既存証跡を再利用し、全テストの再実行を前提にしない |

Git外の通常証跡: `.generated/evidence/wp5-normal-flow-route_a.json`（SHA-256 `0050094f0f7c31b08cbbd433bbf58f771a1f0c046b23173e5085ac0648a0286d`）、`wp5-normal-flow-transport_route_b.json`（`4340fad6e39b197c8d5106b28a199af64a6be2a6394298197ca4483ac2c82bd8`）、`wp5-normal-supervisor-reload.json`、`wp5-normal-integration-progress.json`。raw token/cookie/password/鍵は報告に含めない。

ゴールはKong標準優先の顧客要件デモで、本番FAPI完全準拠環境ではない。stock本文を維持し、PAR client_id欠落はRFC 9126の仕様gapとして記録する。iss欠落guard、追加の開始CSRF防御、DPoP、厳密な個別失効SLAは今回の完了条件に追加しない。RootはSol 6.1 / High、開発委譲はLuna / xHigh。

隔離証跡は再実行せず維持する。直結v6の実AS15件join、2回refresh/rotation、iss不一致拒否のreceipt SHA-256は`9b628ed21e550432405697ee7ac4281fb3b98936c0a087120774ec9ec3424ebd`。通常フローの成功をAS observer再計測や全worker/全background形態の網羅と読み替えない。

以下は5a実行中の履歴であり、上記現在地を置き換えない。

追加進捗（2026-10-04）: 再入計測用image v4のbuildとRoot archive reviewはPASS。network対照でinternal networkからhost loopbackへの到達失敗を確認し、成功済みdirect v3と同じ専用bridgeへ補正した。stock v4はrelayでPARを受信したが、署名検査前のform guardで拒否（HTTP500 / par_form）。ASへ未転送でclaimは未検証、専用環境の回収はRoot独立確認済み。stock v5はresponse_mode=queryへの補正後、client_id guardで拒否（HTTP500 / par_client_id、署名未検証・AS未転送）。固定SDKはPKJWT認証時にform client_idを除去するがRFC9126では必須であり、公開設定での保持経路は見つからなかった。利用者はstock本文の無変更転送を維持し、仕様gapは開示だけにする方針を決定。[ADR0019](decisions/0019-wp5-stock-claim-fixture-boundaries.md)に具体案を記録した。v5の専用リソース・port・private fixture回収もRoot独立確認済み。再入r4は3モードPASS・Root独立確認済みで、同一PARの再入count2/3/4、canonical行数[1,1,0]、HTTP401一致、cleanup PASS。記録は[stock preview](design/third-party-wp5-observer-preview.md)と[再入preview](design/third-party-wp5-reentry-preview.md)を参照。

過去のreceipt `1791014398144929000`には190 candidates中10 secret matches / 2 credential patternsが記録されていた。後続receipt `1791019160834567000`では分類境界を検証し直し、194/194 candidatesのscanが0 secret / 0 patternで完了した。以前のreceiptはimmutableのまま保持し、raw lines/valuesは保存していない。INFO levelはWP3 isolated fixture限定で、通常Composeはnoticeのまま。TLS 1.3 policyと1001件目HTTP parser provenanceは最終receiptでpassした。

effective TLS helperはAdmin要求値と分離し、pinned NGINX configとHTTP/API listener policyを検査する。最新runtimeでは`ssl_conf_command` scopeを含むstrict proofとhandshake controlsがpassし、旧needs-design receiptは履歴として保持する。

WP3のquery-token guardは最新mainの37/37 isolated runtime receiptに含まれる。decoded query namesの`access_token`/alias、duplicate、PDK error/truncation、1000件境界を固定401 challengeで拒否し、query value、body、cookieは読まない。この補完はstock OIDCの機能ではない。

> [!IMPORTANT]
> この文書は Auth0 を使った初期デモの完了時点を記録しています。次の開発では Keycloak-only 構成を採用します。実装要件は [Keycloak FAPI 2.0 デモ要件](design/fapi2-keycloak-requirements.md)、設計判断は [ADR 0007](decisions/0007-keycloak-only-fapi2-demo.md)を参照してください。

## 2026-09-22 の終了時点

利用者の指示により、Gateway 3.16 のデモ検証を現在の状態で終了しました。次の作業では追加要件を確認してください。以下の古い試行記録を、そのまま実行待ちの作業と解釈しないでください。

### 確認済みの結果

- ローカル data plane は Kong Gateway 3.16.0.0 で Konnect に接続しました。ブラウザーフローで使う Gateway endpoint は `https://localhost:8443`、UI は `https://localhost:3443` です。
- engineering のブラウザーログインは `engineering/engineering-route` を表示しました。sales の `sales/sales-route` は利用者が別のブラウザーセッションで確認しました。
- 両方の httpbin 応答では `Authorization` と `Cookie` が欠落していました。
- engineering の認証済みセッションから `sales/sales-route` を偽装して送っても、httpbin は `engineering/engineering-route` を受け取り、UI は PASS を表示しました。
- 最後の対象を絞った `make deck-diff` は作成・更新・削除がすべて 0 でした。`make validate` と `make deck-validate` も通りました。

### 次の要件確認に残す事項

1. **PAR:** `enable_par` と `kong/kong-par.yaml` は用意済みですが、既定の `TF_VAR_enable_par=false` のままです。Auth0 プラン、Highly Regulated Identity の権利、テナント全体への影響、Dashboard の PAR 設定を確認してください。変更前に Terraform と decK のプレビューをレビューし、ブラウザーで `/oauth/par` を検証します。
2. **クライアント認証:** `client_secret_basic` でログインが成功しました。`client_secret_post` への再変更は、追加要件がある場合にだけ検討します。Auth0 と Kong の設定は揃えてください。`client_auth: [none]` は保留された試案で、実装待ちの項目ではありません。
3. **本番向けの制御:** FAPI 2.0 全体、送信者制約付き token、非対称鍵での client 認証、高可用性は、このデモの対象外でした。
4. **以前の認証情報転送:** Request Transformer の同期前に、httpbin へ access token と localhost cookie が届いたことを確認しています。現在の構成では届きません。影響した localhost アプリのセッション更新を利用者へ推奨しましたが、完了は未確認です。
5. **稼働環境:** 追加の外部変更、コンテナー停止、destroy は終了時に依頼されていません。

## 重要な調査経緯

Gateway 3.15 では Auth0 からの callback が 401 になりました。`client_secret_post` と `client_secret_basic` の切り替えだけでは解決しませんでした。3.14 への一時的な切り替えも試しましたが、ブラウザーテストは完了していません。3.16 でも当初は同じ失敗が続きました。

直接確認すると、Konnect の OIDC plugin の `client_secret` が空でした。Auth0 Terraform provider の Management API token に `read:client_credentials` または `read:client_keys` がなく、Terraform output も空だったためです。利用者が scope 追加を承認し、Dashboard で設定した後、refresh-only の計画と decK 差分をレビューして適用しました。plugin に secret が入ると token 交換まで進みました。

次に `jws algorithm (HS256) is disabled` が発生しました。Auth0 client の ID token 署名を Terraform で RS256 に設定し、レビュー済みの計画を適用すると、engineering のブラウザーログインと claim のヘッダー設定が成功しました。Auth0 API の access token の署名方式とは別の設定です。

最初の httpbin 応答には bearer token と cookie がありました。UI をルーティング証跡のみの表示へ修正し、Request Transformer で `Authorization` と `Cookie` を Upstream リクエストから削除しました。レビュー済みの decK 差分を同期した後、httpbin に認証情報が届かないことを確認しました。

偽装テスト用ヘッダーがブラウザーの CORS preflight で拒否されたため、localhost:3000 の許可ヘッダーへ `X-Demo-Department` と `X-Demo-Route` だけを追加しました。同期後の engineering セッションでは、偽装値ではなく認証済み claim の値が届きました。

## 共用 Auth0 テナントに関する注意

検証に使った Auth0 テナントは共用です。既定の `Username-Password-Authentication` 接続は新しい regular web client に自動で有効になり、デモ用接続との競合でログインに失敗しました。既定接続の他アプリへの割り当てを維持しつつ、Gateway client だけを外す必要がありました。`auth0_connection` data source の `enabled_clients` は live API より少ない値を返したため、書き戻し前には `GET /api/v2/connections/{id}/clients` で実際の一覧を確認してください。

公開用リポジトリには、このテナントのドメイン、client ID、connection ID、control plane ID を収録しません。既存の Terraform state と live リソースには以前のデモ名が残っています。名前を変更した設定を現在の環境へ適用する前に、既存リソースとの対応、Terraform plan、decK diff を個別に確認してください。

デモユーザーのパスワードは機密の Terraform output にあります。文書やチャットへ貼り付けないでください。詳細な失敗と対処は [障害対応記録](troubleshooting-log.md)を参照してください。
