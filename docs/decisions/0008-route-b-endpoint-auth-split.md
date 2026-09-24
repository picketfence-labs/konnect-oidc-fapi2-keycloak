# ADR 0008: Route BのPKJWTをendpointごとに分担する

- Status: Accepted
- Date: 2026-09-23

## Context

Route Bは、Keycloak token endpointへの`private_key_jwt`とTLS client certificateの同時提示が必要である。Kong Gateway 3.16.0.0のOpenID Connect pluginは、単一のendpoint requestで`private_key_jwt`生成分岐とmTLS transport分岐を同時には選択しない。

一方、同pluginはPAR、token、revocationの認証方式を個別に設定できる。`client_jwk`のRSA秘密パラメーターはVault referenceを受け付ける。これにより、秘密JWKをKonnectやdecK stateへ保存せず、data planeの環境変数Vaultから解決できる。

## Decision

1. Route Bのtokenとrefresh requestは、`fapi-client-auth-bridge`がPS256 client assertionを生成し、stock OIDC pluginの`tls_client_auth` transportへ渡す。
2. Route BのPAR requestは、stock OIDC pluginの`private_key_jwt`認証を使う。
3. Route Bのrevocation requestも、stock OIDC pluginの`private_key_jwt`認証を使う。
4. custom pluginとstock OIDC pluginは、同じ生成済みRSA鍵を使う。
5. decK stateには公開パラメーター`n`と`e`、および秘密パラメーターへのVault referenceだけを記録する。
6. RSA秘密パラメーター`d`、`p`、`q`、`dp`、`dq`、`qi`は、data planeの`ROUTE_B_JWK`環境変数から`{vault://env/route-b-jwk/...}`で解決する。
7. Keycloakには、同じ鍵から生成した公開鍵だけを登録する。
8. upstream mTLSのclient certificateと秘密鍵もenvironment Vault referenceで解決し、decK stateには値を記録しない。CA certificateは公開情報としてdecK実行時にYAML-safeな文字列へ変換する。

## Consequences

- PAR、token、refresh、revocationの全要求が同じclient identityと鍵に収束する。
- tokenとrefreshだけがPKJWTとmTLS transportを同時に使用する。PARとrevocationはPKJWTでclientを認証する。
- 秘密JWKは生成物とdata plane runtimeにだけ存在し、Git、Terraform state、decK stateには入らない。
- upstream mTLS秘密鍵もdata plane runtimeにだけ存在する。decKは`{vault://env/...}`参照だけをKonnectへ送る。
- Gateway 3.16.0.0に固定したintegration testで、各endpointのwire-level認証証跡を確認する必要がある。
- 将来のGateway upgradeでは、OIDC pluginのendpoint別認証とVault reference対応を回帰確認する。
