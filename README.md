# Konnect OIDC ヘッダールーティングのデモ

Kong Gateway 3.16 を Konnect の data plane としてローカルで動かし、Auth0 の認可コードフローでログインします。認証済みユーザーの `department` claim をヘッダーへ設定し、部門に応じて Upstream を選択します。ブラウザー UI は httpbin が受け取った部門とルートの値を表示します。

2026-09-22 時点で Gateway 3.16 のデモ検証は完了しています。検証結果と保留事項は [セッション引き継ぎ](docs/session-handoff.md)を参照してください。追加機能の有効化や稼働環境の変更前には要件を再確認してください。

当初の依頼にあった `OAuth0` は **Auth0** と解釈しています。claim 名は `department` に統一し、Auth0 Action は入力側の誤記 `departement` も受け付けます。

## 構成

1. Terraform が Konnect control plane、data plane 証明書、Auth0 のアプリケーション・API・データベース接続・Action・デモユーザーを作成します。
2. decK が control plane 内の Gateway エンティティを管理します。
3. ローカルの `kong/kong-gateway:3.16.0.0` data plane が mTLS で Konnect に接続します。
4. OpenID Connect plugin が認可コードとセッションを処理し、PKCE S256 を要求します。Auth0 の `department` claim は `X-Demo-Department` に、署名済みの `route` claim は `X-Demo-Route` に設定されます。
5. Route By Header plugin が両ヘッダーの組を確認して Upstream を選びます。3 つの Upstream はすべて同じ httpbin Target を参照します。
6. UI が httpbin の応答からルーティングの証跡を表示します。

Kong の基本ルーターは認証より先に動きます。そのため、このデモでは同じリクエスト中に別の Kong Route を選ぶ代わりに、access フェーズで Upstream を選択します。Gateway の Route と Service はそれぞれ 1 つです。

## 前提条件

- Terraform 1.11 以降、decK 1.53 以降、Docker Compose、Python 3
- control plane の作成と Gateway 設定が可能な Konnect PAT
- Auth0 Terraform provider 用の Management API アプリケーション。Gateway クライアントの secret を読み取るため、`read:client_credentials` または `read:client_keys` が必要です。
- Auth0 のデモ用テナントを推奨します。ログイン Action はテナント全体に適用されます。

Data plane は Konnect control plane から Enterprise ライセンスを継承します。ローカルの `KONG_LICENSE_DATA` は不要です。

## 設定と起動

`.env.example` を `.env` にコピーし、Konnect と Auth0 の接続情報を入力します。共用 Auth0 テナントでは、既定の database connection に残す client ID を live API で確認し、`TF_VAR_default_db_existing_client_ids` の JSON 配列に設定してください。例の空配列をそのまま使うと既存 client の割り当てが消えるため、plan で必ず確認します。claim namespace の既定値は例示用なので、実利用時は `TF_VAR_claim_namespace` に管理下の URI を設定してください。

```bash
cp .env.example .env
```

```bash
$EDITOR .env
```

```bash
make init
```

```bash
make validate
```

Terraform と decK の変更内容を確認してから、必要な操作だけを実行します。

```bash
make plan
```

```bash
make apply
```

```bash
make deck-diff
```

```bash
make deck-sync
```

```bash
make up
```

<http://localhost:3000> を開いてログインし、画面に部門と論理ルートが表示されることを確認してください。**偽装ヘッダーをテスト**すると、ブラウザーが別部門の値を送っても、Upstream には認証済み claim の値が届くことを確認できます。

デモユーザーのパスワードは機密扱いの Terraform output にあります。

```bash
terraform -chdir=infra output -json demo_users
```

## PAR と FAPI の範囲

PKCE S256 は既定で有効です。PAR は任意です。Auth0 では Enterprise プランの Highly Regulated Identity アドオンと、Dashboard でのテナント設定が必要です。この設定は現在の Auth0 Management API では管理できません。

利用可能なテナントで PAR を有効にする場合は、次の順に進めます。

1. Auth0 Dashboard の **Settings > Advanced** で **Allow Pushed Authorization Requests** を有効にします。
2. `.env` に `TF_VAR_enable_par=true` を設定します。
3. `make plan` の内容を確認してから `make apply` を実行します。
4. `make deck-diff` の内容を確認してから `make deck-sync` を実行します。PAR 用の `kong/kong-par.yaml` が選択されます。

この構成は FAPI 2.0 適合を示すものではありません。送信者制約付きアクセストークンや非対称鍵によるクライアント認証などは対象外です。

## 削除

`make destroy` はローカルコンテナーを停止し、Konnect と Auth0 の Terraform 管理リソースを削除します。control plane の削除に伴い、decK 管理の Gateway エンティティも削除されます。実行時に削除計画を確認してください。

## セキュリティ上の注意

- OIDC plugin が `X-Demo-Department` と `X-Demo-Route` を認証済み claim の値で上書きします。呼び出し元がヘッダーを送っても Upstream を選べません。
- `X-Demo-Route` は署名済みユーザー情報から導く判定用ラベルです。Route By Header plugin が応答に追加する値ではありません。
- デモユーザーのパスワード、data plane の秘密鍵、Auth0 の client secret、Terraform state はローカルに保持し、Git の対象から除外します。
- 共用環境では認証ヘッダーを含むペイロード取得を有効にしないでください。
- 本番用途では共有 secret によるクライアント認証を `private_key_jwt` または mTLS に置き換える必要があります。

## 関連資料

- [設計概要](docs/design-brief.md)
- [設計判断](docs/decisions/0001-identity-aware-upstream-routing.md)
- [障害対応記録](docs/troubleshooting-log.md)
- [セッション引き継ぎ](docs/session-handoff.md)
