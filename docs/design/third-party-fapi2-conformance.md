# 3rd PartyとAPI GatewayのFAPI 2.0必須要件

## この文書の目的

この文書は、Client（3rd Party）とResource Server（API Gateway）がFAPI 2.0 Security Profileへ対応するための必須要件を、実装に依存しない形で列挙する。そのうえで、本デモでの実装担当（3rd Party Gateway、API Gateway、Keycloak）と、Kong Gateway 3.16での充足方法を対応付ける。

3rd Party側でKong Gatewayを使うことは必須ではない。3rd PartyがKong以外のclient実装を選んでも、「要件」列は同じように適用される。「Kongでの充足」列は、本デモの実装例にとっての受入条件である。

- 対象仕様: [FAPI 2.0 Security Profile — Final（2025-02-22）](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- FAPI 2.0 Message Signing（JAR/JARM、署名付きresource request）は別文書であり、任意。本デモの対象外とする。
- 本デモは適合を主張しない。OpenID Foundationの認定も受けない。

## 充足区分

| 区分 | 意味 |
|---|---|
| Stock | Kong Gateway 3.16の標準plugin設定だけで充足する |
| Config | 標準機能で充足するが、既定値から変更する設定が必須 |
| Custom | 本repositoryのcustom pluginで充足する |
| Gap | 標準機能では未充足。補完策を必須とする |
| AS | Authorization Server（Keycloak）の強制で担保し、client側では証跡で確認する |
| N/A | 本デモの構成では該当しない |

Kongの挙動は、`kong-ee` sourceのmaster（2026-09-12）で確認した。**3.16.0.0 runtimeで同じ挙動であることの確認は、実装Issueの受入条件に含める**。

## Client（3rd Party）の必須要件

| ID | FAPI節 | 要件 | 3rd Party Gateway（Kong）での充足 | 区分 | 検証ID |
|---|---|---|---|---|---|
| C-01 | 5.2.1 | TLS 1.2以上を使い、BCP195に従い、server certificateをRFC 9525に従って検証する | KeycloakとAPI Gatewayへの接続で`ssl_verify: true`と`tls_verify: true`を設定し、開発CAだけを信頼する | Config | TLS-01 |
| C-02 | 5.2.2 | （SHOULD）TLS 1.2のserver間接続では、BCP195の推奨cipher suiteだけを許可する | 接続先（Keycloak、API Gateway）でTLS 1.3と推奨suiteへ制限し、TLS 1.2でnegotiateされるsuiteを証跡にする | Config | TLS-02 |
| C-03 | 5.3.3.1、5.2.2.1 | mTLSを使う場合は`mtls_endpoint_aliases`をサポートする | `mtls_token_endpoint`、`mtls_revocation_endpoint`を設定する。値はdiscoveryの`mtls_endpoint_aliases`と一致させる | Config | META-02 |
| C-04 | 5.3.3.1 | sender-constrained access tokenをmTLSまたはDPoPでサポートする | mTLSで統一する。Route Aは`tls_client_auth_cert_id`で、Route Bは`fapi-client-auth-bridge`とstock mTLS transportで実装する | Stock（A）/ Custom（B） | A-CNF-01、B-CNF-01 |
| C-05 | 5.3.3.1 | client認証にmTLSまたは`private_key_jwt`を使う | Route Aは`tls_client_auth`。Route Bはtoken/refreshをbridgeで、PARとrevocationをstock `private_key_jwt`で行う（ADR 0008） | Stock（A）/ Custom（B） | A-PAR-01、B-PKJ-01 |
| C-06 | 5.3.3.1 | access tokenはHTTP headerでだけ送信する | `upstream_access_token_header: authorization:bearer`でAPI Gatewayへ送る | Stock | HDR-01 |
| C-07 | 5.3.3.1 | open redirectorを公開しない | `login_redirect_uri`と`logout_redirect_uri`は固定値だけにする。UIはredirect先をquery parameterから受け取らない | Config | REDIR-01 |
| C-08 | 5.3.3.1 | `private_key_jwt`の`aud`はissuer identifierとし、配列ではなく文字列で送る | bridge（token/refresh）とstock（PAR、revocation）の両方で、`aud`がissuer文字列であることを確認する | Custom / Stock | B-AUD-01、B-AUD-02 |
| C-09 | 5.3.3.1 | refresh tokenとそのrotationをサポートする | refresh responseに新しいrefresh tokenがあれば、それをsessionへ保存する。無ければ既存の値を保持する（`handler.lua`） | Stock | RT-01、RT-ROT-01 |
| C-10 | 5.3.3.1 | AS metadataはmetadata documentから得た値だけを使う。issuerは信頼できる経路で得て、metadataの`issuer`と一致させる | issuerはrepositoryの宣言値を正とする。endpointは、browser用とback-channel用のhostが分かれるため明示設定する。その値がdiscoveryと一致することをテストで保証する | Config | META-01、META-02 |
| C-11 | 5.3.3.1 | 認可の開始はend-userの同意に基づくものに限り、開始をCSRFから保護する | UIの明示的な操作だけで開始する。PKCE verifierと`state`はKongのauthorization cookieでuser agentに束縛される。ただし、cross-siteから開始を誘発されることへの明示的な防御はstockに無い | Gap | CSRF-01 |
| C-12 | 5.3.3.2 | authorization code grantを使う | `auth_methods: [authorization_code, session]` | Stock | A-PAR-01、B-PAR-01 |
| C-13 | 5.3.3.2 | PARを使う | `require_pushed_authorization_requests: true` | Config | PAR-01 |
| C-14 | 5.3.3.2 | PKCE S256を使い、requestごとに新しいchallengeをclientとuser agentへ束縛する | `require_proof_key_for_code_exchange: true`。verifierはauthorization cookieに保存される | Config | PKCE-01 |
| C-15 | 5.3.3.2 | 認可レスポンスの`iss`をRFC 9207に従って検証する | stockは、`iss`があってissuerと一致しない場合は拒否する。**`iss`が欠落した場合は拒否しない**（`kong/openid-connect/authorization.lua`）。Keycloakは`authorization_response_iss_parameter_supported: true`を公開するため、RFC 9207 §2.4により欠落時も拒否が必要 | Gap | ISS-01、ISS-02 |
| C-16 | 5.3.3.2 | authorization endpointへは`client_id`と`request_uri`だけを送る | PAR使用時のredirect URLを証跡で確認する | Stock | PAR-02 |
| C-17 | 5.3.3.2 | （SHOULD NOT）64文字を超える`nonce`を送らない | 既定は18 byteのrandom値をbase64urlにしたもの（24文字） | Stock | PAR-02 |
| C-18 | 5.4.1 | JWTはRFC 8725に従い、PS256、ES256、EdDSAだけを使う。`none`を使わない。RSA鍵は2048 bit以上 | Route BのPKJWTはPS256・RSA 3072 bit。ID tokenのalgorithmはKeycloakのFAPI policyでPS256に強制する | Custom / AS | ALG-01 |
| C-19 | 5.4.2 | client鍵は`jwks_uri`または`jwks`で登録する（推奨） | Keycloak realmへ公開JWKを静的登録する | AS | — |
| C-20 | 5.3.3.1 | DPoPを使う場合はserver nonceをサポートする | DPoPは使わない | N/A | — |

### Client側の補完策（必須）

| Gap | 補完策 | 理由 |
|---|---|---|
| C-15 `iss`欠落を拒否しない | 3rd Party Gatewayのcallback request（`code`または`error`を含むredirect URI requestで、`iss`を含まないもの）を、OpenID Connect pluginより前に`400`で拒否する。まずstockの`pre-function`で実装を試みる。Konnectまたは3.16の制約で使えない場合は、custom pluginへ追加する | 補完がFAPI必須要件の差を埋める唯一の手段で、実装量が小さい |
| C-11 開始のCSRF | 本デモでは**文書化した既知のgapとして受容する**。誘発された開始で成立し得るのは、被害者自身のsession確立だけであり、tokenや認可結果は攻撃者へ渡らない。production化する場合は、UIが発行するCSRF tokenを伴うPOSTで開始するendpointを追加する | stockに防御機構が無い。補完はBFF相当の実装になり、デモの主題から外れる |

## Resource Server（API Gateway）の必須要件

| ID | FAPI節 | 要件 | API Gateway（Kong）での充足 | 区分 | 検証ID |
|---|---|---|---|---|---|
| R-01 | 5.3.4 | access tokenをHTTP headerで受け付け、query parameterでは受け付けない | `bearer_token_param_type: [header]`。**既定値は`[header, query, body]`のため変更が必須** | Config | RS-QUERY-01 |
| R-02 | 5.3.4 | access tokenの有効性、完全性、有効期限、失効状態を検証する | `auth_methods: [introspection]`で、Keycloak introspection endpointへ問い合わせる。`introspection_check_active: true`。失効の反映を遅らせないため、introspection cacheは無効化するか、TTLを30秒以下にする | Config | RS-VALID-01、REVOKE-RS-01 |
| R-03 | 5.3.4 | tokenの認可範囲がrequestを満たすか確認し、満たさなければRFC 6750 §3.1のerrorを返す | `issuers_allowed`、`audience_required: [fapi-demo-api]`、`scopes_required`を設定する。応答の`WWW-Authenticate`を確認する | Config | RS-AUD-01、RS-SCOPE-01、ERR-01 |
| R-04 | 5.3.4 | sender-constrained tokenをmTLSまたはDPoPで検証する | `tls-handshake-modifier`でclient certificateを要求し、`proof_of_possession_mtls: strict`で`cnf.x5t#S256`と照合する | Config | POP-01、POP-02、POP-03 |
| R-05 | 5.2.1、5.2.2 | TLS 1.2以上。browserを経由しないendpointでは、TLS 1.2時にBCP195推奨cipher suiteだけを許可する | `KONG_SSL_PROTOCOLS`と`KONG_SSL_CIPHER_SUITE`（または`ssl_ciphers`）で制限する | Config | TLS-RS-01 |
| R-06 | 5.4.1 | JWTのalgorithmと鍵長の制約 | introspection結果の`active`を正とする。Upstream APIでも署名を再検証し、PS256だけを許可する | Config | ALG-01 |
| R-07 | 5.2.3 | browserから直接呼ばれるendpointではTLS strippingを防ぐ | API Gatewayはbrowserから直接呼ばれない | N/A | — |

### Resource Server側の追加制約（本デモ固有）

- API Gatewayは、検証済みclient certificateをUpstream APIへ`tls-metadata-headers`で転送する。`set_header`でclient供給の同名headerを上書きする。certificateが無いrequestは、それより先に`proof_of_possession_mtls: strict`が`401`で拒否するため、client供給の偽certificate headerはUpstreamへ届かない（HEADER-CERT-01）。
- `tls-handshake-modifier`はCA chainを検証しない（自己署名certificateも受け付ける）。token bindingは`cnf.x5t#S256`との一致で成立する（RFC 8705 §3）。CA chainの検証を追加するかどうかは任意（MAY）とする。

## 参考となるエコシステムの例

- 豪州CDRは、`private_key_jwt`によるclient認証と、mTLS certificate-bound access tokenを必須とする（FAPI 1.0 Advanced基盤）。出典: [CDR Security Profile](https://consumerdatastandardsaustralia.github.io/standards/)
- Brazil Open Finance（FAPI 1.0基盤）は、mTLS channel上で`private_key_jwt`を必須とする。公式文書はJavaScriptで描画されるため、本文の直接確認は未実施。

上記は、Route B（`private_key_jwt` + mTLS）が実運用のエコシステムで採用されている組み合わせであることを示す。Route A（`tls_client_auth` + mTLS）も、FAPI 2.0では同等に有効な選択肢である。
