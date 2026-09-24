# OIDC デモのセッション引き継ぎ

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
