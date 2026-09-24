# ADR 0006: FAPI 2.0二経路をcustom pluginとGHCR imageで実装する

- Status: Superseded by [ADR 0007](0007-keycloak-only-fapi2-demo.md)
- Date: 2026-09-23

## Context

追加デモでは、KongをOIDC Relying Partyとして維持し、次の2経路を比較する。

- Route A: `tls_client_auth` + mTLS certificate-bound access token
- Route B: `private_key_jwt` + mTLS certificate-bound access token

Kong Gateway 3.16.0.0のOpenID Connect実装は、token requestでPrivate Key JWTを生成する分岐と、mTLS client certificateを提示してmTLS endpoint aliasを使う分岐が相互排他になっている。設定だけではRoute Bを実現できない。一方、certificateの読み込みとHTTP clientのmTLS機能は再利用できる。

logoutでは、Kong sessionだけでなくAuth0 SSO sessionとrefresh tokenを終了させる。ブラウザーはAuth0のOIDC Logout endpointを経由する。Auth0が有効な`id_token_hint`を受理した場合、確認画面を省略して直ちにredirectすることがあるため、合格条件は「Auth0 endpointを経由してSSO sessionが終了する」とし、確認promptの常時表示には依存しない。

## Decision

1. Route BはKong coreやBFFではなく、file-based Lua custom pluginで補完する。
2. custom Data Plane imageは`kong/kong-gateway:3.16.0.0`をbaseとし、`ghcr.io/picketfence-labs/konnect-oidc-header-routing`へ発行する。
3. GitHub ActionsからGHCRへ発行し、workflowには`packages: write`を付与する。private packageのpull権限とData Plane hostの認証は実装時に検証する。
4. Route Bのtoken exchange/refreshでは、custom pluginが`aud = issuer`のPrivate Key JWTを生成し、stock OIDCのmTLS transport分岐へ安全に注入する。外部入力の同名parameterは拒否し、内部連携headerはUpstream送信前に削除する。
5. logoutは両Routeで`logout_revoke=true`とし、refresh tokenのrevocationを必須にする。Auth0は`POST /oauth/revoke`で`private_key_jwt`をサポートするため、Route Bではまずstock OIDCの`revocation_endpoint_auth_method=private_key_jwt`を使用する。Route Aは`tls_client_auth`とmTLS revocation endpoint aliasを使用する。
6. access tokenは短寿命かつAuth0の公開手順がrefresh-token revocationを対象とするため、合格条件はrefresh tokenの再利用失敗とする。access tokenはexpiration前に失効するとは表現しない。
7. revocation後、Kong sessionを破棄し、Auth0の`end_session_endpoint`へredirectしてAuth0 SSO sessionを終了する。
8. Auth0がRoute BのrevocationにもmTLS aliasを要求した場合、stock `token:revoke()`はPKJWTとmTLSを同時利用できない。その場合だけcustom pluginのlogout処理へcombined PKJWT + mTLS revocationを追加する。core module monkey patchは行わない。

## Live tenant gate

2026-09-23のread-only確認では、現在のAuth0 tenantは次の状態だった。

- Discovery metadataに`end_session_endpoint`と`revocation_endpoint`は存在する。
- `private_key_jwt`はadvertiseされている。
- `pushed_authorization_request_endpoint`は存在しない。
- `mtls_endpoint_aliases`は存在しない。
- 既存clientに`compliance_level`設定はない。
- 既存resource serverにProof-of-Possession設定はない。

Auth0公式要件ではFAPI compliance、PAR、mTLS sender constrainingはEnterprise Plan + Highly Regulated Identity add-onが必要である。したがって、現在のtenantでは二経路のlive FAPI検証を開始できない。Auth0 administratorがHRI entitlementを確認し、tenant-level PARとmTLS endpoint aliasesを有効化することを実装のexternal gateとする。

## Consequences

- BFFは追加しない。
- Kong本体をforkせず、custom pluginとcustom imageの差分へ閉じ込める。
- GHCR package公開、署名、SBOM、脆弱性scan、pull認証がdelivery scopeへ追加される。
- pluginはKong内部moduleへ依存するため、Gateway 3.16固定testとupgrade regressionが必要になる。
- logout E2Eではrefresh token再利用失敗、Kong cookie失効、Auth0再認証要求を別々に検証する。
- HRIが有効になるまでmock mTLS token/revocation endpointによるwire-level spikeだけを進め、Auth0 FAPI準拠を完了扱いにしない。
