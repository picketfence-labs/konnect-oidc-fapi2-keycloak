# ADR 0010: API Gatewayはintrospectionとmutual TLSのPoPでtokenを検証する

- Status: Accepted（設計PR #5、2026-10-02 merge。runtime未受入）
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

[ADR 0011](0011-customer-demo-scope.md)により、完全適合ではなく顧客向けデモを対象とする。introspection/active検査は標準機能の追加価値として維持するが、個別token失効・logout後の反映SLAはデモの必須受入ではない。

## Decision

1. API Gatewayは`auth_methods: [introspection]`でtokenを検証する。introspection endpointへは、専用のKeycloak client（`api-gateway-introspection`）として`tls_client_auth`で認証する。
2. `introspection_check_active: true`とする。説明しやすさのためcache無効を既定とする。cacheを使う場合はTTLを記録する。失効反映SLAは設定しない。
3. `bearer_token_param_type: [header]`とする。
4. `tls-handshake-modifier`でclient certificateを要求し、`proof_of_possession_mtls: strict`で`cnf.x5t#S256`と照合する。CA chainの検証は必須にしない（RFC 8705 §3のbindingで成立する）。
5. `issuers_allowed`、`audience_required: [fapi-demo-api]`、`scopes_required`で、認可範囲を確認する。
6. `tls-metadata-headers`で、検証済みclient certificateをUpstream APIへ転送する。Upstream APIは、それを`cnf`と再照合する（多層防御）。
7. API GatewayからUpstream APIへは、API Gateway専用のcertificateでmTLS接続する。Upstream APIは、そのcertificate以外からの接続を拒否する。
8. 両Routeのtokenの`aud`に、`fapi-demo-api`と`api-gateway-introspection`を含める。Keycloak 26.7.4のintrospection client audience checkを無効化しない。Resource ServerとUpstream APIの認可には、`fapi-demo-api`を引き続き要求する。

## Consequences

- API Gatewayへのrequestごとに、Keycloakへのintrospectionが発生する（cacheを無効化した場合）。デモの規模では許容する。
- active検査による失効の効果は、任意シナリオ`REVOKE-RS-01`/`RS-REVOKE-01`を実施した場合だけ説明する。デモresetからtoken個別失効を推論しない。
- client供給の`X-Client-Cert`は、certificateが無ければOIDCが先に拒否し、certificateがあれば`tls-metadata-headers`が上書きする。偽装はUpstreamへ届かない。
- 3.16.0.0の実runtimeで、上記のpriority、schema、挙動が同じであることを確認する必要がある。
- CA chainを検証しない既定構成では、自己署名certificateであることだけを拒否理由にしない。`POP-03`は、提示certificateと既存tokenの`cnf`が不一致のfixtureとする（[RFC 8705 §6.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.2)）。
- logoutのHTTP `200`は、access token個別の失効登録を証明しない。厳密な失効を説明する場合だけ、前後の`active`/API応答と、sessionを維持したaccess token単独revokeを追加検証する。

## Alternatives considered

| 案 | 不採用の理由 |
|---|---|
| `auth_methods: [bearer]`でJWTをローカル検証する | 失効状態を確認できず、標準introspectionの追加価値を示せない。短命JWTを失効確認と同一視しない |
| PoP verifierだけで検証する（v1方式） | Resource Serverとしての責務がGatewayに無くなり、3rd Party区間の検証点がUpstreamになる |
| `mtls-auth`でCA chainを検証し、certificateをConsumerへ対応付ける | 3rd Partyごとのconsumer管理が増える。bindingの検証には不要。将来の追加は妨げない |

## Fallback（Design ownerへ戻す条件）

WP2でintrospectionの`active`、`cnf`、audience/claimを確認する。不足した場合は原因とsanitized証跡を報告し、WP3のintrospection実装を止める。まずrealm設定とexact runtimeを確認する。

- token有効性とPoPはP0の前提なので省略しない。Workerが暗黙にbearerへ切り替えて完了扱いにしない。
- Design ownerが別構成を検討する場合は、introspection/activeも使う案を優先する。`auth_methods: [bearer, introspection]`だけではAND検証を保証しない。
- 標準設定で失効検査とPoPを両立できず、新規customが必要なら、デモのP0と本来のFAPI要件の差分・工数を整理して設計を改訂する。JWT署名・有効期限・PoPだけの案はR-02の失効要件を満たさないと開示する。完全適合の必要条件を、今回のデモ目的と混同しない。
- 代替を採用する前に、このADR、要件、Delivery plan、対外説明を更新し合意する。現在の推奨構成を変更したとは扱わない。追加価値の未成立だけを、P0の実現不能と即断しない。

## Keycloak 26.7.4の確認根拠

- [AccessTokenIntrospectionProvider](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java): `verifyAudience`が認証したintrospection client IDをaudienceと照合する。保存tokenからの復元も`cnf`を保持する。
- [OIDCProviderConfig](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/OIDCProviderConfig.java): audience check回避のserver既定値は`false`。
- [TokenRevocationEndpoint](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenRevocationEndpoint.java): refresh revokeでclient sessionを終了する。sessionが既に無効な場合は、access tokenの個別revoke処理を行わず`200`を返し得る。
