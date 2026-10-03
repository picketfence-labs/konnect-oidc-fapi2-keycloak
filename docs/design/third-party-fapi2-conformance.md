# FAPI 2.0要件と顧客向けデモ対応範囲

## この文書の目的

本来のClient/Resource Server向けFAPI 2.0要件を、今回の顧客向けデモの採用範囲と対比する。**仕様の必須要件と、今回のデモの必須要件は同じではない**。P0/P1以外の未対応を理由に完全適合を主張できないが、すべてを今回の開発阻害条件にも設定しない。

- デモ範囲の正本: [ADR 0011](../decisions/0011-customer-demo-scope.md)、[実装要件](third-party-fapi2-requirements.md)
- お客様向け説明: [デモ対応範囲と追加実装](third-party-demo-explainer.md)
- 対象仕様: [FAPI 2.0 Security Profile — Final](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- この表はClient/RSの主要項目の整理であり、ASを含む完全な適合チェックリストや認定結果ではない。OIDF認定も受けない。
- Message Signing（JAR/JARM等）は別仕様。今回の対象外。

### 今回の優先度

| 区分 | 扱い |
|---|---|
| P0 | 顧客必須のmTLS・private_key_jwtを実現する条件。必要ならcustomで補完 |
| P1 | 標準plugin/設定で示す追加価値。必要性を説明し、対象シナリオを検証 |
| F | 将来対応・追加候補。今回のDoDには含めず、未対応を開示 |
| N/A | 選んだ構成では非該当 |

表の「Kongでの充足」は**設計上の対応方法**であり、実装済み・live検証済みを意味しない。実装状況はWPの証跡で判定する。

## 充足区分

| 区分 | 意味 |
|---|---|
| Stock | Kong Gateway 3.16の標準plugin設定だけで充足する |
| Config | 標準機能で充足するが、既定値から変更する設定が必須 |
| Custom | 本repositoryのcustom pluginで充足する |
| Gap | 標準機能では未充足。P0は補完必須、Fは将来対応として開示 |
| AS | Authorization Server（Keycloak）の強制で担保し、client側では証跡で確認する |
| N/A | 本デモの構成では該当しない |

Kongの挙動は、`kong-ee` sourceのmaster（2026-09-12）で確認した。**3.16.0.0 runtimeで同じ挙動であることの確認は、実装Issueの受入条件に含める**。

## Client（3rd Party）: 本来の要件と今回の選択

| ID | FAPI節 | 要件 | 3rd Party Gateway（Kong）での充足 | 区分 | 検証ID | 今回 |
|---|---|---|---|---|---|---|
| C-01 | 5.2.1 | TLS 1.2以上を使い、BCP195に従い、server certificateをRFC 9525に従って検証する | KeycloakとAPI Gatewayへの接続で`ssl_verify: true`と`tls_verify: true`を設定し、開発CAだけを信頼する | Config | TLS-01 | P0 |
| C-02 | 5.2.2 | （SHOULD）TLS 1.2を使うserver間接続では、BCP195の推奨cipher suiteだけを許可する | TLS 1.2を実際に交渉するclient/outbound connectionは、そのsuiteを確認する。API Gateway inboundのTLS 1.3-only方針は別のR-05/TLS-RS-01 evidenceとして検証し、他のpeerへのTLS-02証明と混同しない（[ADR 0016](../decisions/0016-api-gateway-inbound-tls-policy.md)） | Config | TLS-02 | P1 |
| C-03 | 5.3.3.1、5.2.2.1 | mTLSを使う場合は`mtls_endpoint_aliases`をサポートする | PAR/token/refresh/revokeのmTLS aliasとdiscoveryの対応を確認する。Route Bの全endpointとmetadata取得へmTLSを補完する（DP0契約、ADR 0012） | Config / Custom | META-02、B-TRANSPORT-01、AS-META-MTLS-01 | P0 |
| C-04 | 5.3.3.1 | sender-constrained access tokenをmTLSまたはDPoPでサポートする | mTLSで統一する。Route Aは`tls_client_auth_cert_id`で、Route Bはbridgeとstock mTLS transportで実装し、ASのPAR/revokeにもmTLSを補完する | Stock（A）/ Custom（B） | A-CNF-01、B-CNF-01 | P0 |
| C-05 | 5.3.3.1 | client認証にmTLSまたは`private_key_jwt`を使う | Route Aは`tls_client_auth`。Route BはPKJWT + mTLSを全認証endpointで使う。token/refreshはbridge送信時delegate、PAR/revokeはstock PKJWT + 専用transport plugin | Stock（A）/ Custom（B） | A-PAR-01、B-PKJ-01 | P0 |
| C-06 | 5.3.3.1 | access tokenはHTTP headerでだけ送信する | `upstream_access_token_header: authorization:bearer`でAPI Gatewayへ送る | Stock | HDR-01 | P1 |
| C-07 | 5.3.3.1 | open redirectorを公開しない | `login_redirect_uri`と`logout_redirect_uri`は固定値だけにする。UIはredirect先をquery parameterから受け取らない | Config | REDIR-01 | P1 |
| C-08 | 5.3.3.1 | `private_key_jwt`の`aud`はissuer identifierとし、配列ではなく文字列で送る | DP0で確定したtoken/refresh/PAR/revokeの全実装で、`aud`がissuer文字列であることを確認する | Stock / Custom（ADR 0012） | B-AUD-01、B-AUD-02 | P0 |
| C-09 | 5.3.3.1 | refresh tokenとそのrotationをサポートする | refresh responseに新しいrefresh tokenがあれば、それをsessionへ保存する。無ければ既存の値を保持する（`handler.lua`） | Stock | RT-01、RT-ROT-01 | P1 |
| C-10 | 5.3.3.1 | AS metadataはmetadata documentから得た値だけを使う。issuerは信頼できる経路で得て、metadataの`issuer`と一致させる | issuerはrepositoryの宣言値を正とする。endpointは、browser用とback-channel用のhostが分かれるため明示設定する。その値がdiscoveryと一致することをテストで保証する | Config | META-01、META-02 | P1 |
| C-11 | 5.3.3.1 | 認可の開始はend-userの同意に基づくものに限り、開始をCSRFから保護する | UIの明示操作、stockのstate/PKCEを維持する。ただし開始CSRF防御を満たすと主張しない。専用開始endpoint等は将来対応 | Gap | CSRF-01 | F |
| C-12 | 5.3.3.2 | authorization code grantを使う | `auth_methods: [authorization_code, session]` | Stock | A-PAR-01、B-PAR-01 | P1 |
| C-13 | 5.3.3.2 | PARを使う | `require_pushed_authorization_requests: true` | Config | PAR-01 | P1 |
| C-14 | 5.3.3.2 | PKCE S256を使い、requestごとに新しいchallengeをclientとuser agentへ束縛する | `require_proof_key_for_code_exchange: true`。verifierはauthorization cookieに保存される | Config | PKCE-01 | P1 |
| C-15 | 5.3.3.2 | 認可レスポンスの`iss`をRFC 9207に従って検証する | stockは、`iss`があってissuerと一致しない場合は拒否する。**`iss`が欠落した場合は拒否しない**（`kong/openid-connect/authorization.lua`）。Keycloakがiss対応を宣言する場合の欠落拒否は、本来必要な追加対策。今回guardは作らず、将来`pre-function`優先で補完する | Gap | ISS-01、ISS-02 | F |
| C-16 | 5.3.3.2 | authorization endpointへは`client_id`と`request_uri`だけを送る | PAR使用時のredirect URLを証跡で確認する | Stock | PAR-02 | P1 |
| C-17 | 5.3.3.2 | （SHOULD NOT）64文字を超える`nonce`を送らない | 既定は18 byteのrandom値をbase64urlにしたもの（24文字） | Stock | PAR-02 | P1 |
| C-18 | 5.4.1 | JWTはRFC 8725に従い、PS256、ES256、EdDSAだけを使う。`none`を使わない。RSA鍵は2048 bit以上 | Route BのPKJWTはPS256・RSA 3072 bit。ID tokenのalgorithmはKeycloakのFAPI policyでPS256に強制する | Custom / AS | ALG-01 | P0 |
| C-19 | 5.4.2 | client鍵は`jwks_uri`または`jwks`で登録する（推奨） | Keycloak realmへ公開JWKを静的登録する | AS | — | P1 |
| C-20 | 5.3.3.1 | DPoPを使う場合はserver nonceをサポートする | 必須mTLS経路ではDPoPを使わない。DP1で追加経路のclient側proof生成・nonce対応を調査する | N/A | — | F |

Route AのStock区分はclient認証方式を指す。Route Aの送信境界guardとmetadata mTLSにもcustom transportが介在する。AS側peer計測は[test-only証跡契約](third-party-as-peer-evidence.md)で固定し、標準認証機能とは説明しない。

### 補完の優先順位

| 対象 | 今回の判断 | 追加実装 |
|---|---|---|
| PKJWTとmTLSの同時使用（C-03〜05、08） | **顧客必須**。PAR/revokeをserver-only HTTPSへ下げない | 既存bridgeのtoken/refresh対応に加え、AS全back-channelを専用transport pluginで補完（[DP0契約](third-party-as-mtls-transport.md)、ADR 0012）。内部API依存は3.16.0.0へ固定しdrift検出 |
| discovery/JWKS、bridgeの独自discovery | **mTLS接続方針の対象**。cold cacheも確認 | stockでclient certが送れない呼出しだけ補完。証跡がないまま標準対応と記載しない |
| C-15 iss欠落拒否 | F。今回の顧客必須ではない | 本来の対応にはcallback guardが必要。将来は`pre-function`優先、不可ならcustom plugin。提示されたissの不一致拒否はstockで維持 |
| C-11 開始CSRF | F。今回の顧客必須ではない | 将来はCSRF対策付き開始endpoint等を設計。stock state/PKCEだけで開始CSRF対策済みと説明しない |

開始CSRFとiss欠落の除外は、2026-10-02の利用者の目的明確化と続行承認に基づく**デモ範囲の変更**であり、未検証の安全性の承認ではない。専用のgap受容を待つことを今回の開発ゲートにしない。対外説明の開示は必須とする。

## Resource Server（API Gateway）: 本来の要件と今回の選択

| ID | FAPI節 | 要件 | API Gateway（Kong）での充足 | 区分 | 検証ID | 今回 |
|---|---|---|---|---|---|---|
| R-01 | 5.3.4 | access tokenをHTTP headerで受け付け、query parameterでは受け付けない | `bearer_token_param_type: [header]`。**既定値は`[header, query, body]`のため変更が必須** | Config | RS-QUERY-01 | P1 |
| R-02 | 5.3.4 | access tokenの有効性、完全性、有効期限、失効状態を検証する | `auth_methods: [introspection]`、`introspection_check_active: true`。専用client IDをtokenのaudienceに加え、Keycloakのaudience checkを維持する。cache無効を既定としactive検査を使う。個別失効・logout後の反映SLAの厳密な受入は対象外。成立しなければDesign ownerが再設計し、本来要件の部分対応を開示する | Config | RS-VALID-01、RS-INT-AUD-01、RS-INT-AUD-02、RS-REVOKE-01、REVOKE-RS-01 | P1 |
| R-03 | 5.3.4 | tokenの認可範囲がrequestを満たすか確認し、満たさなければRFC 6750 §3.1のerrorを返す | `issuers_allowed`、`audience_required: [fapi-demo-api]`、`scopes_required`を設定する。応答の`WWW-Authenticate`を確認する。RS-AUD-01では隔離Keycloakの`pop-verifier-audience` access/introspection claimを同時に一時無効化し、tokenとactive introspection双方でAPI audience欠落を確認する。別のintrospection audience mapperは不変、完全復元後は新しいgrantで両audienceとAPI `200`を確認する | Config | RS-AUD-01、RS-SCOPE-01、ERR-01 | P1 |
| R-04 | 5.3.4 | sender-constrained tokenをmTLSまたはDPoPで検証する | `tls-handshake-modifier`でclient certificateを要求し、`proof_of_possession_mtls: strict`で`cnf.x5t#S256`と照合する | Config | POP-01、POP-02、POP-03 | P0 |
| R-05 | 5.2.1、5.2.2 | TLS 1.2以上。browserを経由しないendpointでは、TLS 1.2時にBCP195推奨cipher suiteだけを許可する | API inboundは`KONG_SSL_CIPHER_SUITE=modern`のTLS 1.3-only policyを目標とする。exact runtime effective protocol allowlist/cipher preset、negotiated TLS 1.3 AEAD、offer済みTLS 1.2-only/weak-suiteのprotocol-layer拒否、HTTP/Upstream非到達、直後のpositive controlを検証する。証跡が揃わない場合は受入にしない（[ADR 0016](../decisions/0016-api-gateway-inbound-tls-policy.md)） | Config | TLS-RS-01 | P1 |
| R-06 | 5.4.1 | JWTのalgorithmと鍵長の制約 | introspection結果の`active`を正とする。Upstream APIでも署名を再検証し、PS256だけを許可する | Config | ALG-01 | P1 |
| R-07 | 5.2.3 | browserから直接呼ばれるendpointではTLS strippingを防ぐ | API Gatewayはbrowserから直接呼ばれない | N/A | — | N/A |

### Resource Server側の追加制約（本デモ固有）

- API Gatewayは、client供給の`Cookie`、`X-Demo-*`、case/underscore/unknown suffixを含む`X-Fapi-*`と`X-Client-Cert*`をroute-scoped pre-functionで除去し、その後OIDC/TMHが検証済みclaim、URL-encoded certificate PEM、5種の固定stock certificate detail headerを生成する。これはstockのautomatic prefix removalではなく[ADR 0015](../decisions/0015-api-resource-server-header-boundary.md)のinline Lua補完である。生成されたdetailは認証判断に使わず、caller sentinel/未知suffix/alias/重複が残らないこととfingerprint-to-leaf一致を確認する。1000個の上限到達やtruncationはfail closedにする（HEADER-CERT-01）。
- `tls-handshake-modifier`はCA chainを検証しない（自己署名certificateも受け付ける）。token bindingは`cnf.x5t#S256`との一致で成立する（[RFC 8705 §6.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.2)）。`POP-03`は既存tokenの`cnf`と一致しない自己署名certificateを使い、binding不一致を検証する。正しく束縛された自己署名certificateをCA外という理由だけで拒否する要件ではない。CA chain検証を追加する場合は、binding検査とは別のポリシーと証跡を明記する（MAY）。
- API listenerのTLS 1.3-only policyはFAPI最低値TLS 1.2以上より強い選択である。`TLS-RS-01`のTLS 1.2 offer拒否はeffective `modern`/TLS 1.3-only metadata、実際のClientHello offer、protocol-layer peer rejection、HTTP/Upstream非到達、直後のTLS 1.3 valid controlが揃うまで未受入とする。weak suiteをofferしただけではcipher rejectionの証明にならない。
- 1001個目のwell-formed headerがGatewayより前のHTTP parserに拒否される場合、そのHTTP 400はLuaの431とは異なる。固定imageと実行中Nginx configで`max_headers` overrideがないこと、既知default 1000件のsource、`client sent too many header lines`とAPI pathを結び付けたbounded in-memory log count delta、正確なwire count、同じ認証fixtureのunder-limit positive、Upstream counter不変、sentinel非転送、response非漏えい、negative後のpositive controlが揃った場合に限り安全境界の証拠候補とする。条件が揃わないHTTP 400はneeds-designまたはfailのままとする（[ADR 0015](../decisions/0015-api-resource-server-header-boundary.md)）。

P1のR-02は標準introspection/active検査の採用を示す。表に挙げたRS-REVOKE-01/REVOKE-RS-01は任意の追加説明用であり、個別失効保証の厳密な検証まで完了したという意味ではない。C-15は欠落拒否がF、提示されたissの不一致拒否（ISS-01）はstockのP1として維持する。

## DPoPの追加候補（DP1）

Kong OIDCにはResource Server側のDPoP proof検証機能がある（[公式FAPI/DPoP説明](https://developer.konghq.com/plugins/openid-connect/#demonstrating-proof-of-possession-dpop)）。ただし、この事実から、KongをRPとする今回の3rd Party経路でproof生成・token取得・API request・server nonce対応まで自動実現できるとは推論しない。

DP1はDesign ownerが、Keycloak 26.7.4の対応、Kong 3.16.0.0の`proof_of_possession_dpop`/`dpop_use_nonce`、client/BFFまたはcustomによるproof生成、nonce/replay、mTLSとの共存を確認する。追加経路の工数と証跡を提案し、実装着手は別途合意する。mTLSの代替として必須経路を置き換えない。FAPIはsender constraintとしてmTLS **または** DPoPを選べるため、両方のデモ実装が完全適合の一律必須ではない。
