# 設計概要

2026-09-22 に利用者の指示で Gateway 3.16 のデモ検証を終了しました。認証済みユーザー 2 名のルーティングと、engineering ユーザーのヘッダー偽装防止を確認しています。追加要件は [セッション引き継ぎ](session-handoff.md)を読んでから検討してください。

## 目的

Auth0 OIDC の認可コードログイン、claim の取得、安全なヘッダー設定、認証情報に基づく Upstream 選択をブラウザーで再現します。Kong Gateway 3.16 のローカル data plane は Konnect control plane に接続します。

## 要件

- Auth0 を IdP として使用する。当初の `OAuth0` は Auth0 と解釈する。
- `department` を取得し、入力側の誤記 `departement` も許容する。
- 認証済み claim から Upstream に送るヘッダーを設定する。
- そのヘッダーでルーティングする。
- Gateway Service と外部 backend Target は各 1 つとする。
- ブラウザーの認可コードフローと結果 UI を提供する。
- Konnect と Auth0 の基盤リソースは Terraform、Gateway エンティティは decK で管理する。
- 作成と削除を宣言的に実行できるようにする。
- FAPI 関連の任意機能と推奨設定を示す。

## 構成

- Route は `/api/demo`、Service は `oidc-httpbin-service`。
- `sales`、`engineering`、`default` の 3 つの Upstream は同じ HTTPS httpbin Target を参照する。
- OpenID Connect plugin（priority 1050）が claim を `X-Demo-Department` と `X-Demo-Route` に設定する。
- Auth0 Action が `department` から署名済み `route` claim を導く。
- Route By Header plugin（priority 850）が両ヘッダーの組で Upstream を選ぶ。
- Request Transformer が認証と Upstream 選択の後に `Authorization` と `Cookie` を削除する。
- UI は httpbin の応答からルーティングに必要な値だけを表示する。

基本ルーターは認証 plugin より先に動くため、同じリクエストで生成したヘッダーを Kong Route の条件にはできません。この設計では access フェーズで Upstream を切り替え、Route と Service を 1 つずつ維持します。

## FAPI に関する判断

- 既定は認可コード、セッション、PKCE S256。
- PAR は Auth0 `/oauth/par` と Kong OIDC の設定で任意に有効化する。
- Auth0 の PAR は有料アドオンとテナント設定が必要で、現在の Management API からテナント設定を変更できないため、既定では無効にする。
- FAPI 2.0 全体への適合は対象外とする。

## 検証条件

| 項目 | 確認方法 | 合格条件 |
|---|---|---|
| IaC 構文 | `make validate` | Terraform、Compose、YAML、静的チェックが通る |
| 基盤変更のプレビュー | `make plan` | 意図した Konnect・Auth0 リソースだけが変わる |
| Gateway 変更のプレビュー | `make deck-diff` | `oidc-routing-demo` タグの対象だけが変わる |
| data plane 接続 | Konnect UI と Gateway ログ | 接続済みで cluster エラーがない |
| 認可コードと PKCE | ブラウザーログイン | Auth0 ログイン後に UI へ戻る |
| ヘッダー設定 | UI と httpbin 応答 | `X-Demo-Department` がユーザー metadata と一致する |
| Upstream 選択 | UI、httpbin 応答、設定 | 部門と署名済み `X-Demo-Route` が選択規則に一致する |
| 偽装防止 | UI から矛盾するヘッダーを送る | OIDC claim の値が優先される |
| 任意の PAR | 有効化後の Auth0 通信 | `/authorize` より先に `/oauth/par` を呼ぶ |

## 対象外

- 本番可用性、HA、独自ドメイン、WAF、監査ログ保持、FAPI 認証
- 実顧客の ID とデータ
- 2 つのデモ用規則を超える動的なポリシー管理

## 保留事項

- [x] US の Konnect API endpoint に接続し、Gateway 3.16 の data plane を確認した。
- [x] 共用 Auth0 テナントの既存アプリと接続設定を維持した。
- [ ] Auth0 プランが Highly Regulated Identity と PAR を利用できるか確認し、有効化の要否を判断する。
- [x] data plane のライセンスは Konnect control plane から継承した。
- [x] engineering と sales のブラウザーログインで部門とルートを確認した。sales の結果は利用者による報告。
- [x] engineering で偽装ヘッダーを送っても、httpbin は認証済み claim の値を受け取った。
