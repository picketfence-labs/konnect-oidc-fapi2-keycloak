# ADR-0004: Auth0 の ID token を RS256 で署名する

- 日付: 2026-09-22
- 状態: 決定済み

## 背景

Gateway 3.16 の OIDC client secret を修復した後、callback は token endpoint に到達しましたが 401 になり、Kong は `jws algorithm (HS256) is disabled` と記録しました。Auth0 アプリケーションの `jwt_configuration.alg` は Terraform で指定していませんでした。デモ API の access token が RS256 でも、ID token とは別の設定です。

## 決定

Terraform の `auth0_client.gateway.jwt_configuration.alg` を `RS256` にします。Kong の署名検証は有効のままにし、Auth0 の JWKS で検証します。

## 影響

変更対象はデモ用 Auth0 client のみです。Terraform plan で確認してから適用し、認可コードフローとヘッダー設定を再検証しました。
