# ADR 0010: API Gatewayはintrospectionとmutual TLSのPoPでtokenを検証する

- Status: Proposed
- Date: 2026-10-01

## Context

[ADR 0009](0009-third-party-client-gateway-topology.md)により、既存のKong GatewayはResource Serverとなる。FAPI 2.0 Security Profile §5.3.4は、Resource Serverに次を求める。

- access tokenをHTTP headerで受け付け、query parameterでは受け付けない
- access tokenの有効性、完全性、有効期限、**失効状態**を検証する
- sender-constrained tokenを検証する

JWTのローカル検証だけでは、失効状態を確認できない。Kong OpenID Connect pluginの`bearer_token_param_type`は、既定値で`query`と`body`を含む。

Kong `kong-ee` master（2026-09-12）のsourceでは、次を確認した。

- `proof_of_possession_mtls`は、`bearer`と`introspection`の両方で`cnf`を照合する。client certificateの取得には、`tls-handshake-modifier`か`mtls-auth`が必要である（schemaの検証で強制）。
- `tls-handshake-modifier`はclient certificateを要求するが、CA chainは検証しない。
- `tls-metadata-headers`（priority 996）は、`ssl_client_escaped_cert`を`set_header`で上流へ設定する。
- OpenID Connect plugin（priority 1050）は、上記2つより先に実行される。

## Decision

1. API Gatewayは`auth_methods: [introspection]`でtokenを検証する。introspection endpointへは、専用のKeycloak client（`api-gateway-introspection`）として`tls_client_auth`で認証する。
2. `introspection_check_active: true`とする。失効の反映を遅らせないため、introspectionのcacheは無効化するか、TTLを30秒以下にする。
3. `bearer_token_param_type: [header]`とする。
4. `tls-handshake-modifier`でclient certificateを要求し、`proof_of_possession_mtls: strict`で`cnf.x5t#S256`と照合する。CA chainの検証は必須にしない（RFC 8705 §3のbindingで成立する）。
5. `issuers_allowed`、`audience_required: [fapi-demo-api]`、`scopes_required`で、認可範囲を確認する。
6. `tls-metadata-headers`で、検証済みclient certificateをUpstream APIへ転送する。Upstream APIは、それを`cnf`と再照合する（多層防御）。
7. API GatewayからUpstream APIへは、API Gateway専用のcertificateでmTLS接続する。Upstream APIは、そのcertificate以外からの接続を拒否する。

## Consequences

- API Gatewayへのrequestごとに、Keycloakへのintrospectionが発生する（cacheを無効化した場合）。デモの規模では許容する。
- logoutでrevokeされたaccess tokenは、API Gatewayで拒否される。この効果を受入シナリオ`REVOKE-RS-01`で示せる。
- client供給の`X-Client-Cert`は、certificateが無ければOIDCが先に拒否し、certificateがあれば`tls-metadata-headers`が上書きする。偽装はUpstreamへ届かない。
- 3.16.0.0の実runtimeで、上記のpriority、schema、挙動が同じであることを確認する必要がある。

## Alternatives considered

| 案 | 不採用の理由 |
|---|---|
| `auth_methods: [bearer]`でJWTをローカル検証する | 失効状態を確認できない。FAPI 2.0 §5.3.4を満たすには、短命tokenを根拠とするリスク受容が別途必要になる |
| PoP verifierだけで検証する（v1方式） | Resource Serverとしての責務がGatewayに無くなり、3rd Party区間の検証点がUpstreamになる |
| `mtls-auth`でCA chainを検証し、certificateをConsumerへ対応付ける | 3rd Partyごとのconsumer管理が増える。bindingの検証には不要。将来の追加は妨げない |

## Fallback

Keycloakのintrospection応答が`cnf.x5t#S256`を含まない場合は、次のいずれかで扱う。どちらを選んだかは、実装PRとこのADRへ記録する。

1. `auth_methods: [bearer]`でJWTをローカル検証してPoPを照合し、introspectionは`active`の確認だけに使う構成を、Kong 3.16で組めるか確認する。
2. 組めない場合は、`bearer` + 短命access token（5分以下）でのリスク受容を、明示的なgapとして記録する。
