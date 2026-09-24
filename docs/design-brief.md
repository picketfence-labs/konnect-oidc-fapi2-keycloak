# 設計概要

2026-09-22 に Auth0 を使った初期デモの検証を終了しました。認証済みユーザー 2 名のルーティングと、engineering ユーザーのヘッダー偽装防止を確認済みです。

次の開発では IdP を Keycloak に置き換え、FAPI 2.0 の主要なセキュリティ要素を比較できるデモへ拡張します。実装要件は [Keycloak FAPI 2.0 デモ要件](design/fapi2-keycloak-requirements.md)、設計判断は [ADR 0007](decisions/0007-keycloak-only-fapi2-demo.md)を正とします。[セッション引き継ぎ](session-handoff.md)は初期デモの実績と注意事項を記録しています。

## 目的

同じブラウザー向け認可コードフローを使い、token endpoint のクライアント認証方式だけが異なる次の 2 経路を比較します。

| 経路 | token endpoint のクライアント認証 | 送信者制約 |
|---|---|---|
| Route A `/api/fapi/mtls` | `tls_client_auth` | mTLS certificate-bound access token |
| Route B `/api/fapi/pkj-mtls` | `private_key_jwt` | mTLS certificate-bound access token |

両経路で Authorization Code、PAR、PKCE S256、証明書バインドトークンの検証、refresh token の revoke、Kong セッション破棄、Keycloak の RP-Initiated Logout を実演します。

## 初期デモから維持する要件

- 認証済み `department` claim を Upstream 向けヘッダーへ設定する。
- `department` と入力側の誤記 `departement` を正規化する。
- 認証済み claim から導いた値で Upstream を選択する。
- 呼び出し元が送る偽装ヘッダーを信頼しない。
- Upstream へ `Authorization` と `Cookie` を転送しない。
- ブラウザー UI で選択経路、クライアント認証方式、PoP 検証結果、論理ルートを確認できるようにする。

## 目標構成

- Keycloak を Authorization Server、OpenID Provider、ログイン UI として使用する。
- Route A と Route B を別の Kong Route と Gateway Service に分離する。
- Route A は標準 OpenID Connect plugin の mTLS client authentication を使う。
- Route B は最小限の file-based Lua plugin で `private_key_jwt` client assertion を生成し、標準 OpenID Connect plugin の mTLS token transport を再利用する。
- 両経路で mTLS certificate-bound access token を発行し、PoP verifier が `cnf.x5t#S256` と TLS peer certificate を照合する。
- custom Data Plane image は `kong/kong-gateway:3.16.0.0` を base とし、`ghcr.io/picketfence-labs/konnect-oidc-fapi2-keycloak` へ発行する。
- Konnect と Keycloak の設定を宣言的に再現し、秘密鍵と証明書はリポジトリへ収録しない。

## Route B の custom plugin 境界

custom plugin は `private_key_jwt` assertion の生成と token request への注入だけを担当します。BFF、Kong core fork、独自 OIDC クライアントは追加しません。

assertion は Keycloak の issuer を `aud` とし、短い有効期間、一回限りの `jti`、非対称署名を使います。外部リクエストから渡された `client_assertion` と `client_assertion_type` は破棄します。詳細な契約と失敗条件は要件書に定義します。

## ログアウト

ログアウトボタンは次の順で処理します。

1. refresh token を Keycloak の revocation endpoint で revoke する。
2. Kong のセッションを破棄する。
3. Keycloak の `end_session_endpoint` へ遷移する。
4. `post_logout_redirect_uri` で UI に戻り、再アクセス時に再認証が必要であることを確認する。

確認画面の表示は Keycloak のセッション状態や設定に依存するため、必須の合格条件にはしません。Keycloak の SSO セッションが終了し、保護対象へ無認証で戻れないことを合格条件にします。

## 検証条件

| 項目 | 合格条件 |
|---|---|
| 静的検証 | `make validate` が通る |
| Route A | `tls_client_auth` で token を取得し、証明書バインドを検証できる |
| Route B | `private_key_jwt` で token を取得し、証明書バインドを検証できる |
| PAR と PKCE | 両経路が PAR と PKCE S256 を使用する |
| 認証方式の分離 | Route A と Route B の設定、鍵、ログ証跡を区別できる |
| PoP 正常系 | `cnf.x5t#S256` と TLS peer certificate の thumbprint が一致する |
| PoP 異常系 | 証明書なし、別証明書、thumbprint 不一致を拒否する |
| assertion 異常系 | 期限切れ、誤った `aud`、`jti` 再利用、誤署名を拒否する |
| ヘッダー偽装防止 | Upstream が認証済み claim 由来の値だけを受け取る |
| ログアウト | token revoke、Kong session 破棄、Keycloak SSO session 終了を確認できる |

## 対象外

- Entra ID と Auth0 を使った FAPI 経路
- FAPI 2.0 Security Profile への正式な認証取得
- DPoP-bound access token
- BFF と Kong core fork
- 本番可用性、HA、独自ドメイン、WAF、監査ログの長期保持
- 実顧客の ID とデータ

## 開発着手時の順序

1. [要件書](design/fapi2-keycloak-requirements.md)と [ADR 0007](decisions/0007-keycloak-only-fapi2-demo.md)をレビューする。
2. Keycloak realm、2 clients、FAPI policy、鍵と証明書の生成方法を宣言する。
3. Route A を標準 plugin だけで成立させる。
4. Route B の最小 custom plugin と custom image を追加する。
5. PoP verifier と logout orchestration を追加する。
6. UI と証跡を追加し、要件書の正常系と異常系を自動化する。
