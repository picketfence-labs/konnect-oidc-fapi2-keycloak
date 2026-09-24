# ADR 0007: KeycloakだけでFAPI 2.0二経路デモを構成する

- Status: Accepted
- Date: 2026-09-23
- Supersedes: [ADR 0006](0006-fapi-custom-plugin-ghcr-logout.md)のAuth0依存部分

## Context

追加デモでは、Kong GatewayをOIDC Relying Partyとして維持し、次の2経路を比較する。

- Route A: `tls_client_auth` + mTLS certificate-bound access token
- Route B: `private_key_jwt` + mTLS certificate-bound access token

現在のAuth0 tenantはPARとmTLS endpoint aliasesを公開していない。必要なHighly Regulated Identity add-onも確認できない。Microsoft Entra IDのmTLS bearer transportはpreviewで、applicationごとのMicrosoft側enablementが必要である。返却tokenも通常のBearer tokenなので、今回の一般的なRFC 8705 certificate-bound token検証には合わない。

Keycloak 26.7.4はFAPI 2.0 Security Profile用client policy、PAR、Private Key JWT、mTLS client authentication、mTLS certificate-bound access token、token revocation、RP-Initiated Logoutを提供する。Keycloakはlocal userも管理できるため、upstream IdPは不要である。

## Decision

1. KeycloakだけをAuthorization Server、OpenID Provider、login providerとして使用する。
2. Entra ID federationは今回の必須scopeに含めない。
3. Keycloakはlocal demo usersを認証し、`department`と`route` claimsを発行する。
4. Route Aはstock OpenID Connect pluginの`tls_client_auth`を第一候補にする。
5. Route Bはfile-based Lua custom pluginで`private_key_jwt`とmTLS transportを併用する。
6. 両RouteでPAR、PKCE S256、authorization code lifetime、client assertion algorithm、sender-constrained tokenをKeycloak client policyで強制する。
7. 両Routeのaccess tokenとrefresh tokenを、token request時にKongが提示したcertificateへバインドする。
8. PoP verifier APIはJWT検証に加え、`cnf.x5t#S256`とTLS peer certificateのSHA-256 thumbprintを照合する。
9. custom Kong imageは`kong/kong-gateway:3.16.0.0`をbaseとし、`ghcr.io/picketfence-labs/konnect-oidc-fapi2-keycloak`へ発行する。
10. logoutはrefresh token revocation、Kong session破棄、Keycloak RP-Initiated Logoutの順で行う。

## Consequences

- Auth0 TerraformとAuth0固有Actionはtarget architectureから外れる。
- Keycloak container、realm import、truststore、client certificates、local usersが追加される。
- Keycloakが発行者になるため、demo全体をlocal DockerとKonnect data planeで再現できる。
- Entra login、MFA、Conditional Accessは対象外になる。必要になった場合はKeycloak identity brokerとして別ADRで追加する。
- Keycloak client adaptersはPoP verificationを代行しない。専用PoP verifier APIが必要である。
- FAPI 2.0 Security Profileの要件を検証するが、OpenID Foundation certification取得はscopeに含めない。

## Implementation contract

詳細要件と受入条件は[Keycloak FAPI 2.0 demo requirements](../design/fapi2-keycloak-requirements.md)を正とする。
