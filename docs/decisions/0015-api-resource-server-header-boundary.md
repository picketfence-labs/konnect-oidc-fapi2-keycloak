# ADR 0015: API Resource Serverは入力由来headerを先に除去する

- Status: Proposed（WP3実装とexact runtime受入で検証し、このPRのmerge時に合意する）
- Date: 2026-10-03
- Relates to: [ADR 0010](0010-api-gateway-resource-server-validation.md)、[ADR 0014](0014-reuse-existing-api-ca.md)

## Context

API Resource Serverはintrospection結果のnamespaced claimから`X-Demo-Department`と`X-Demo-Route`を作る。TLS Metadata Headers pluginは必須設定`inject_client_cert_details: true`により、接続client certificateのURL-encoded PEMを`X-Client-Cert`へ転送し、Serial、Issuer-DN、Subject-DN、Fingerprint、Chainのstock detail headerも生成する。これらのdetailは信頼済みGateway由来の診断情報であり、認証やRoute選択には使わない。clientが同名headerや`X-Fapi-*`を先に送る場合、入力値を除去してからOIDC/TMHが検証済みclaim/certificate由来headerを生成する順序を固定版runtimeで確認する必要がある。

literal header nameのremove設定だけでprefixや未知suffixまで除去できるとは仮定しない。Kong PDKの`kong.request.get_headers(max_headers)`は既定で最大100個を返す。取得上限に達した後のheaderを検査できると仮定すると、最後に置かれた`X-Fapi-*`や`X-Client-Cert*`が残る危険がある。

## Decision

1. API Routeにだけstock `pre-function`を置き、OIDCとTLS Metadata Headersより前に、header名をcase-insensitiveに正規化して入力由来の`Cookie`、すべての`X-Demo-*`、すべての`X-Fapi-*`、すべての`X-Client-Cert*`、`client_assertion*`を消す。underscore表記もdashへ正規化して同じ境界に含める。
2. Luaはheader名とPDKが返した値tableをmemory内でのみ扱う。header value内容を解釈せず、value typeと配列長だけを重複entry数の判定に使う。値を認証、Route/certificate選択、ログ、receiptへ使わない。PDK取得が失敗・truncatedの場合と、明示limit 1000に達した場合はrequestを431でfail closedにする。上限内ならOIDCが検証済みclaimから`X-Demo-*`を設定し、TMHが接続certificateの`X-Client-Cert`とstock detail headerを設定する。
3. GatewayからUpstreamへclient-originの認証情報としてJWT再検証用`Authorization`だけを保持する。Cookieとclient供給の`X-Fapi-*` / `X-Client-Cert*` / `client_assertion*`は転送しない。TLS Metadata Headersが生成した`X-Client-Cert`と、正確なstock detail header 5種だけは転送し、Upstreamはpeer/certificate/token bindingを検証したうえで受け入れる。detail headerは認証判断に使わない。
4. この補完はstockの自動prefix除去機能ではなく、route-scoped inline Luaである。新規file-based pluginやcore patchを追加せず、認証方式、introspection、PoP、issuer/audience/scopeの決定は変更しない。
5. exact Kong 3.16.0.0 runtimeで、header名のcase変化、未知suffix、101個目および1001個目に置く攻撃header、1000個ちょうどのfail-closed、Cookie、`X-Demo-*`偽装、OIDC/TMH trusted overwrite順を検証する。stock/plugin schemaの受理、Lua handler実行、実TLSへの到達を別の証跡として扱う。Gatewayより前のHTTP parserが1001件目を拒否する場合、そのHTTP 400はLuaの431とは区別する。
6. 同じroute-scoped `pre-function`に、OIDCより前のquery credential guardを置く。`kong.request.get_query(1000)`で得るdecoded parameter namesだけを調べ、case-insensitiveに`access_token`とdash/underscore aliasを拒否する。token value、raw query、body、cookieを読まず、queryをrewrite/stripしない。PDK error、nil/truncated、malformed shape、1000引数到達も固定401と`WWW-Authenticate: Bearer error="invalid_token"`でfail closedにする。有効なAuthorization headerがあってもquery credential nameを拒否し、無害なqueryは通常のOIDC検証へ進める。この追加Luaはstock OIDCのheader-only設定を補足するものであり、stockの挙動として説明しない。
7. LEAK-01 lifecycle logのcredential判定では、候補値を次の狭いsource/path/equality条件でのみ`noncredential_protocol_identifier`として数える。実際のtoken応答collectionに属するtop-level `session_state`は、同じ応答のaccess tokenが既存のPS256/issuer/time/audience/scope/PoP検証を通り、その署名済み`sid`と値が完全一致し、`azp`がそのgrant client IDに一致した後だけ分類する。実際のauthenticated introspection responseはHTTP成功・`active is true`で、既存の同一token introspection検証を通った後、top-level `azp`、`jti`、`sid`、`sub`の各値が同一tokenの検証済みclaimと完全一致する場合だけ分類する。candidate collectionとverified tokenの結び付きも照合する。pending candidateはbounded memory内に保持し、未検証・不一致・inactive・error・overflowの場合に元のcookie/unknown categoryへ戻してlog scanする。CookieJar/HTTP Cookie、nested/arbitrary fields、explicit credential category、unknown valuesは対象外で、credential pattern scanも維持する。
8. form submissionの構造的`name` memberが文字どおり`username`である場合だけ、そのfield nameをfixed protocol constantとして数える。対応する`value`やpassword、他のfield name/valueは通常のcandidate分類を維持する。API request-target scanでfixed constant扱いにするqueryは、`API_PATH?probe=small`と`API_PATH?`に`x=1`を1000個連結した完全一致の2つだけである。追加argument、encoded variant、credential-bearing query、その他のtargetは通常どおりsensitive candidateである。この分類はログのcredential predicateにだけ適用し、API response scanは引き続きstrictにcandidateを評価する。

## Consequences

- Luaはheader nameを調べ、PDK値tableのtypeと配列長を上限判定にだけ使う。header value内容は認証やRoute/certificate選択へ使わず、log/receiptへ保存しない。AuthorizationだけはUpstreamの署名・audience・scope再検証のため保持し、WP4 verifierがその再検証を行う。
- Luaが受け取ったheader entryが1000件に達した場合、またはPDKが取得に失敗/truncateした場合は431で拒否する。HTTP parserが先に拒否したことをLuaの上限検査実行と説明しない。
- 1001件目のrequestを安全境界として受け入れるには、well-formedな正確なwire header count、pinned imageと実行中Nginx configに`max_headers` overrideがないこと、既知default 1000件のsource、bounded in-memory logで`client sent too many header lines`と公開API request pathの該当countがrequest前後で各1増えること、同じ認証fixtureによるunder-limit positive control、拒否前後で不変のUpstream counter、caller sentinelが転送されないこと、responseにsecretがないこと、negative後のpositive controlを記録する。raw logはreceiptに保存しない。これらが揃わないHTTP 400、malformed request、harness failure、reset、timeoutはpassにしない。parser拒否のphase/layerは`NGINX parser`とし、Lua 431に読み替えない。
- inline Luaによる補完の正確な役割とscopeをPR・利用者向け説明へ記載する。標準機能による保証と説明しない。標準OIDC/TMHの認証、必須のTLS metadata生成、このheader境界補完を区別する。
- API listenerはAPI runtime migration後の内部Compose networkでだけ使う。通常demoの`make up` readiness gate、WP5入口制御、UI閉鎖を緩めない。
- 次回の隔離診断fixtureでは、Nginxのheader-limit INFO markerをbounded scanで観測する目的に限り、WP3専用ComposeのKong log levelを`info`にする。通常Composeは`notice`のまま維持する。この診断差分は通常設定のruntime受入を直接実証したとは扱わない。raw logsはmemory内だけで調べ、既存のsecret/pattern判定を維持する。
- `noncredential_protocol_identifier`はrestricted correlation dataであり、credential matchとは分けて有限enum/countとしてreceiptに残す。raw identifierとtoken/hashはreceiptへ出さない。過去のLEAK-01 receiptは変更しない。最終WP3 receipt `wp3-runtime-receipt-1791019160834567000.json`で194/194 candidate scanが0 secret/pattern matchesとなり、この狭い分類のexact runtime動作を検証した。Keycloak 26.7.4 sourceはtoken response `session_state`とsigned `sid`の対応を示すが、同じ値のCookieが認証に使われた証拠ではない。

## Acceptance evidence

- static state検査でroute scope、fail-closed上限、全prefix/大小文字/underscore処理、stock OIDC/TMH設定を確認する。
- exact 3.16.0.0 runtimeでplugin schema、handler priority、listener SNI、TLS証明書要求、PoP、header forwardingを確認する。
- 101+/1001+headerの最後にunknown-suffix攻撃headerを配置してUpstreamへ到達しないことを確認する。1001件目がHTTP parserで拒否される場合は上記のparser provenanceとcontrolsを別途満たす。Lua単体・fake PDKのみの成功はruntime受入へ読み替えない。
- query-only token、encoded/case/dash/underscore alias、duplicate、late `access_token`、1000件境界、truncated 1001件を有効Bearer headerとともにexact runtimeで試し、固定401 challengeとUpstream不到達を確認する。no-queryおよび無害なquery controlはUpstreamへ到達することを確認する。Lua単体試験は補助でありruntime受入へ読み替えない。
- 最終isolated receiptでは37/37 acceptance rowsがPASSし、cleanupを独立確認した。これは通常Control Plane migration/syncやWP5 transportの受入を意味しない。

## References

- [Kong PDK `kong.request.get_headers`](https://developer.konghq.com/gateway/pdk/reference/kong.request/)
- [Kong Request Transformer Advanced plugin](https://developer.konghq.com/plugins/request-transformer-advanced/)
- [NGINX `max_headers`](https://nginx.org/en/docs/http/ngx_http_core_module.html#max_headers)
- Keycloak 26.7.4 [`AccessTokenResponse.session_state`](https://github.com/keycloak/keycloak/blob/26.7.4/core/src/main/java/org/keycloak/representations/AccessTokenResponse.java), [`IDToken.sid`](https://github.com/keycloak/keycloak/blob/26.7.4/core/src/main/java/org/keycloak/representations/IDToken.java), [`JsonWebToken.jti`](https://github.com/keycloak/keycloak/blob/26.7.4/core/src/main/java/org/keycloak/representations/JsonWebToken.java), and [`AccessTokenIntrospectionProvider`](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java).
