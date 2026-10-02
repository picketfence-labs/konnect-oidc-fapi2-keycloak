# 3rd Party経由FAPI 2.0デモ要件

## この文書の目的

この文書は、既存の二経路デモ（[Keycloak FAPI 2.0二経路デモ要件](fapi2-keycloak-requirements.md)、以下「v1要件」）に3rd Partyを追加した構成について、実装契約を定義する。顧客向けデモの必須範囲と、本来のFAPI 2.0適合との差分を分ける。補完方式は[DP0契約](third-party-as-mtls-transport.md)と[ADR 0012](../decisions/0012-third-party-as-mtls-transport.md)に固定した。ローカル設計完了・レビュー/merge待ちであり、実装・runtime受入とは分ける。Workerへ方式選択を渡さない。

- デモの目的・優先順位: [ADR 0011](../decisions/0011-customer-demo-scope.md)
- お客様向け説明: [デモ対応範囲と追加実装](third-party-demo-explainer.md)
- 設計判断の正本: [ADR 0009](../decisions/0009-third-party-client-gateway-topology.md)、[ADR 0010](../decisions/0010-api-gateway-resource-server-validation.md)
- 本来のFAPI要件と今回の優先度の対応表: [FAPI 2.0要件とデモ対応範囲](third-party-fapi2-conformance.md)
- 作業分割と検証方法: [Delivery plan](third-party-delivery-plan.md)

要件キーワード（MUST、SHOULD、MAY）は、**今回のデモ内の実装契約**を示し、FAPI 2.0完全適合を意味しない。この文書に記載のない事項は、v1要件を継続して適用する。v1要件と矛盾する場合は、この文書を優先する。

## 目的と優先順位（2026-10-02）

お客様がFAPI 2.0対応を検討する際に、Kongで主要要件を実現できる**実際に動くデモ**を提供する。本番想定の完全適合・認定を達成するProjectではない。前回デモで不足した3rd Partyを組み込み、特に3rd Partyとの通信がmTLSであることを証跡付きで示す。

| 優先度 | 今回の扱い |
|---|---|
| P0 顧客必須 | 3rd PartyのAS・APIへのサーバー間通信をmTLS化し、Route AのmTLS client認証とRoute Bの`private_key_jwt`を動かす。不足する標準機能はcustom plugin等で補完する |
| P1 標準機能の追加価値 | PAR、PKCE S256、token検証、header限定、issuer/audience/scope、refresh等を設定し、必要性と証跡を説明する。標準設定で実現できる範囲を採用する |
| D デモ運用 | logout/reset後に、新しい認可フローで別Route・別userのテストを実行できる。個別token失効保証や反映SLAは求めない |
| F 将来・追加候補 | DPoP、開始CSRFの追加防御、`iss`欠落guard、本番運用・完全適合の検証。未対応を開示し、今回のDoDとは分ける |

P0を弱めて追加価値を達成することはしない。追加価値の実現に新たなcustom実装が必要と判明した場合は、Design ownerが必要性・工数・制約を整理して範囲を再提案する。すべてのFAPI要件を満たすまでデモを止めるという契約にはしない。

## 変更の要約

| 観点 | v1（現行main） | 本要件 |
|---|---|---|
| FAPI client（RP） | Kong Gateway | **3rd Party**。実装例として**3rd Party Gateway**（新設のKong） |
| Resource Server | PoP verifier API | **API Gateway**（既存のKong）。PoP verifierは**Upstream API**として残す |
| 利用者の経路 | UI → Kong → PoP verifier | UI → 3rd Party Gateway → API Gateway → Upstream API |
| Konnect control plane | 1つ | **2つ**（API用と3rd Party用。組織境界を表す） |
| client認証の方式 | Route A / Route B | 両Routeを維持し、3rd Party Gatewayへ移す。Route BのAS向けmTLSを拡張する |
| sender constraint | mTLS | 変更なし。mTLSで統一する |

既存の直接経路（UIからKongへのRoute A/B）は残さず、3rd Party経由の経路で置き換える。

## 目標

1. 3rd PartyがKeycloakとの認可コードフローでsender-constrained access tokenを取得し、API Gateway経由でUpstream APIを呼べること。
2. 3rd Partyのclient認証を、Route A（`tls_client_auth`）とRoute B（`private_key_jwt`）の2方式で比較できること。
3. API Gatewayが、client認証方式に依存しない**単一の検証ポリシー**で両Routeのtokenを検証すること。
4. 本来のFAPI 2.0要件、今回のデモで示す機能、標準機能と追加実装、将来対応を区別して説明できること。

## 完成時の利用者体験

1. 利用者は3rd PartyのUIでRoute AまたはRoute Bを選ぶ。
2. 3rd Party GatewayがKeycloakへPARを送る。
3. 利用者はKeycloakのlocal demo userでloginする。
4. 3rd Party Gatewayは、選んだRouteのclient認証でauthorization codeを交換する。
5. Keycloakは、3rd Party GatewayのRoute別client certificateに束縛したaccess tokenとrefresh tokenを返す。
6. 3rd Party Gatewayは、同じcertificateでAPI GatewayへmTLS接続し、Bearer tokenを送る。
7. API Gatewayはintrospectionとcertificate bindingを検証し、claim由来のheaderを設定して、Upstream APIへ転送する。
8. UIは次を表示する: client認証方式、token `cnf`、API Gatewayが受け取ったTLS peer certificateのthumbprint、`azp`、`department`、logical route。
9. logout/resetでRoute cookieとKeycloak SSO sessionを終了し、UIへ戻る。次のケースは新しい認可フローで実行する。stock revocationも使用するが、個別access tokenの失効保証をデモ完了条件にしない。

## Target architecture

### Runtime components

| Component | 組織 | Responsibility |
|---|---|---|
| Demo UI | 3rd Party | Route選択、結果表示、logout、negative testの起動 |
| 3rd Party Gateway（Kong 3.16.0.0） | 3rd Party | FAPI client: PAR、PKCE、client認証、code exchange、session、refresh、revocation、logout。API GatewayへのmTLS接続 |
| `fapi-client-auth-bridge` custom plugin | 3rd Party | Route B token/refreshのissuer-audience PKJWTを送信時に生成するsigner delegate。client供給assertion拒否とissuer確認も継続 |
| `fapi-as-mtls-transport` custom plugin（新規） | 3rd Party | 全AS back-channelのmTLS transport、Route/metadata cert選択、送信時signer呼出し、retry/redirect拒否。DP0/ADR 0012の固定契約で実装 |
| Keycloak 26.7.4 | Authorization Server | local login、FAPI policy、token発行、introspection、revocation、logout |
| API Gateway（Kong 3.16.0.0） | API提供者 | Resource Server: client certificateの要求、introspection、certificate bindingの検証、claim由来headerの設定、Upstreamへの転送 |
| Upstream API（PoP verifier） | API提供者 | API GatewayからのmTLS接続だけを受け付ける。JWT署名を再検証し、転送されたclient certificateと`cnf`を照合する多層防御。sanitizedなevidenceを返す |
| Konnect control plane × 2 | — | API Gateway用と3rd Party Gateway用に、構成を別々に配布する |

### 接続とcertificate

| 区間 | TLS | 提示するclient certificate | 信頼の根拠 |
|---|---|---|---|
| Browser → UI、Browser → 3rd Party Gateway | HTTPS | なし | 開発CA |
| 3rd Party Gateway → Keycloak（Route A: PAR、token、refresh、revoke） | mTLS | Route A cert | `tls_client_auth`。Keycloak clientへの登録 |
| 3rd Party Gateway → Keycloak（Route B: PAR、token、refresh、revoke） | mTLS | Route B TLS cert | PKJWTでclient認証。token/refreshは提示certへ束縛。PAR/revokeにも専用transport pluginでmTLSを補完（ADR 0012） |
| 3rd Party Gateway → Keycloak（discovery、JWKS。bridge自身のdiscovery取得も含む） | mTLS | 専用3rd Party metadata cert | 公開情報の取得にもmTLSを使う。TLS peer検証とissuer一致を維持。DP0のtransport decoratorで全呼出しを補完 |
| 3rd Party Gateway → API Gateway | mTLS | **tokenの取得時と同じ**Route別cert | `cnf.x5t#S256`との一致 |
| API Gateway → Keycloak（introspection） | mTLS | API Gateway introspection cert | Keycloak clientへの登録 |
| API Gateway → Upstream API | mTLS | API Gateway upstream cert | Upstream APIが信頼するcertの固定 |

mTLS transport、OAuth client認証、tokenのcertificate bindingは別の役割である。Route Bは全back-channelでmTLS transportを使い、OAuth client認証にはPKJWTを使う。この追加要件はFAPI自体が全endpointへ一律要求するものではなく、今回の顧客向けデモの接続方針である（[FAPI §5.2.2.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.2.2.1)）。v1のADR 0008をそのまま継続せず、[ADR 0011](../decisions/0011-customer-demo-scope.md)で3rd Party構成に限って変更する。

ブラウザーのlogin、authorization redirect、callback、RP-Initiated LogoutはHTTPSとし、browserへclient certificateを配布しない。管理API・Konnect control plane接続も顧客向けデータ経路とは別扱いにする。実行時にuserinfo等の追加AS back-channelが生じる場合は、未記載だからHTTPSでよいとせず、DP0の通信inventoryにない呼出しは拒否し、追加要否をDesign ownerへ戻す。

Keycloakはbrowserと同じTLS listenerを使うため、`KC_HTTPS_CLIENT_AUTH: request`を維持し、提示されたcertを開発CAで検証する。サーバー間の実際のrequestにcertが提示・検証された証跡を必須にする。**AS listener全体でcertなしを拒否する`required`構成ではない**。顧客へ「ASの全入口がmTLS強制」とは説明しない。API Gatewayはcert欠落・binding不一致を拒否する。この区別は[説明資料](third-party-demo-explainer.md)にも明記する（[Keycloak 26.7.4 TLS設定](https://github.com/keycloak/keycloak/blob/26.7.4/docs/guides/server/mutual-tls.adoc)）。

v1要件の「Key material」は継続し、次の鍵材料を追加する。用途ごとに別々の鍵材料を使うこと（MUST）。

- 専用3rd Party metadata client certificate（DP0で採用。OAuth clientとしては登録しない）
- API Gateway server TLS
- API Gateway introspection client authentication
- API Gateway → Upstream APIのclient certificate

3rd Party Gateway server TLS（browser向け）は、v1のKong proxy certificateを引き継いでよい（MAY）。

### Network and ports

| Service（compose） | Host port | 用途 |
|---|---|---|
| `ui` | 3443 | 3rd PartyのUI |
| `kong-third-party` | 8443 | 3rd Party Gateway。browserからのredirect先 |
| `kong-api` | 9443 | API Gateway。compose network内では`kong-api:8443`。host portはnegative testの直接requestにだけ使う |
| `keycloak` | 8444 | Authorization Server |
| `pop-verifier` | 公開しない | Upstream API |

3rd Party Gatewayのbrowser向けportを8443に据え置くことで、redirect URIのhostとportをv1から変えずに済む。

### Container images

v1要件の「Container images」を継続する。両Gatewayは同じcustom image（`ghcr.io/picketfence-labs/konnect-oidc-fapi2-keycloak`）を使ってよい（MAY）。API Gatewayでは`KONG_PLUGINS`に`fapi-client-auth-bridge`と`fapi-as-mtls-transport`を含めず、entityも置かない（MUST NOT）。3rd Partyでは両pluginのロード、transportのglobal entity、bootstrap envを必須にする（MUST）。[DP0のpreflightゲート](third-party-as-mtls-transport.md)を通常入口/UI公開前の必須段階とし、静的plugin/global entity照合と設定反映後の全worker ready確認が揃わなければ入口を開かない。transport未ロード時のRoute Aはこのゲートで防ぎ、bridge access拒否は期待しない。bridgeもRoute B accessでready transport context/epoch無しを拒否する。その他のpluginもGatewayごとに必要最小限にする（SHOULD）。test-only Keycloak observer imageは[peer証跡契約](third-party-as-peer-evidence.md)に従い、標準Keycloakの通常デモimageとは分ける。

## Keycloak requirements

v1要件の「Realm」「Demo userとclaim」「FAPI policy」を継続する。clientは次のとおり置き換える。

| Client ID | 役割 | client認証 | 備考 |
|---|---|---|---|
| `third-party-fapi-mtls` | 3rd Party Route A | `tls_client_auth` | v1 `kong-fapi-mtls`を置換 |
| `third-party-fapi-pkj-mtls` | 3rd Party Route B | `private_key_jwt`（token/refreshは同時にmTLS） | v1 `kong-fapi-pkj-mtls`を置換 |
| `api-gateway-introspection` | API GatewayのResource Server | `tls_client_auth` | introspection専用。authorization code flowを許可しない |

- 3rd Party clientのredirect URIは、`https://localhost:8443/api/fapi/mtls`と`https://localhost:8443/api/fapi/pkj-mtls`とすること（MUST）。
- 両3rd Party clientのaccess tokenの`aud`は、resource audienceの`fapi-demo-api`とintrospection client IDの`api-gateway-introspection`を両方含むこと（MUST）。v1のaudience `pop-verifier`は、`fapi-demo-api`へ置き換える。Keycloak 26.7.4のintrospectionは、認証したclient IDがtokenのaudienceにあるかを検査する。server/clientのaudience checkを無効化して回避しないこと（MUST NOT）。API GatewayとUpstream APIは、引き続き`fapi-demo-api`を要求する。
- access tokenは`azp`（3rd Party clientのclient ID）を含むこと（MUST）。Upstream APIは、Route識別にheaderではなく`azp`を使う。
- 両Routeの有効なtokenを`api-gateway-introspection`でintrospectionした応答は、`active: true`、`cnf.x5t#S256`、上記の`aud`、`scope`、namespaced claimを含むこと（MUST）。必要な項目が欠ける場合はintrospection構成の着手を止め、ADR 0010のFallbackに従ってDesign ownerへ戻す。P0のtoken有効性・PoP検証を省略して進めない。
- refresh token rotationの検証用に、3rd Party clientでrefresh tokenの再発行（Keycloakの「Revoke Refresh Token」相当）を切り替えられること（SHOULD）。既定は無効とする（FAPI 2.0 §5.3.2.1）。

## 3rd Party Gateway requirements

v1要件の「Route A OpenID Connect configuration」は実行場所を移して継続する。Route B custom plugin契約とLogout契約は、以下とADR 0011で変更する。

- Route Aのpathは`/api/fapi/mtls`、Route Bのpathは`/api/fapi/pkj-mtls`とすること（MUST）。
- 各RouteのServiceは、`https://kong-api:8443/fapi-api/evidence`を対象にすること（MUST）。`client_certificate`には、そのRouteのtoken取得に使ったものと同じCertificate entityを指定すること（MUST）。
- API Gatewayのserver certificateを、開発CAで検証すること（MUST、`tls_verify: true`）。
- access tokenは`Authorization: Bearer`でだけ送ること（MUST）。
- stock OIDCが行う`state`と提示された`iss`の不一致検査を維持すること（MUST）。`iss`欠落拒否の追加guardは今回の必須範囲ではなく、完全適合へ向けた将来対応とする。実装するなら`pre-function`を第一候補とする（conformance C-15）。
- ASの全back-channelでclient certificateを提示し、server certificateを検証すること（MUST）。Route BのPAR/revoke、stock/bridgeのdiscovery・JWKS取得を含め、DP0で確定した補完方式を実装する。設定にcert IDが存在するだけでmTLS成功とは判定しない。
- refresh responseに新しいrefresh tokenがある場合は、それをsessionへ保存すること（MUST、conformance C-09）。
- 3rd Party Gatewayの静的endpoint設定（authorization、token、PAR、revocation、end-session、JWKS、mTLS alias）は、discoveryの値と一致すること（MUST）。一致はテストで確認する。
- client供給の`client_assertion`、`client_assertion_type`、`X-Client-Cert*`、`X-Demo-*`、`X-Fapi-*`は、API Gatewayへの転送前に除去すること（MUST）。

### Logout/reset（デモ運用）

- 通常経路はstock OIDCのlogout、Route cookie破棄、Keycloak RP-Initiated Logoutを使う。stockのrefresh/access revokeも有効にするが、専用の失効順序制御や追加pluginは作らない。
- 両Routeで、reset後に旧Route sessionが再利用されず、新しいauthorization code flowで別Route・別userの結果を表示できること（MUST）。自動logoutでSSO等が残る場合は、cookie消去とKeycloakの対象demo user session終了を行う**文書化した手動reset**を許容する。全realmのsessionを無差別に削除しない。
- revocation requestを送る場合は、P0のmTLS + 各Routeのclient認証を満たすこと（MUST）。HTTP `200`は処理応答であり、個別access token失効の証明ではない。revokeが拒否/失敗してもcertなし再送・自己判断のrevoke無効化をしない。stock logoutが中断する場合は上記の対象demo user限定の手動resetで次ケースへ進み、revoke結果とreset結果を別記録にする。
- `RS-REVOKE-01`、`REVOKE-RS-01`の厳密な失効検証は追加説明用の任意シナリオとする。リセット成功から、旧tokenの再使用拒否や本番向け失効SLAを推論しない。

## API Gateway requirements

API Gatewayは1つのServiceと1つのRoute（path `/fapi-api/evidence`）で、両Routeのtokenを同じポリシーで検証すること（MUST）。

| 項目 | 要件 |
|---|---|
| client certificate | `tls-handshake-modifier`でclient certificateを要求する（MUST）。compose network内（SNI `kong-api`）とhost（SNI `localhost`）の両方から要求されることを確認する |
| token取得 | `bearer_token_param_type: [header]`（MUST）。queryやbodyのtokenは受け付けない |
| token検証 | `auth_methods: [introspection]`、`introspection_endpoint_auth_method: tls_client_auth`、`introspection_check_active: true`（MUST） |
| introspection cache | デモで挙動を説明しやすくするため無効化を既定とする。cacheを使う場合はTTLを記録する。logout/resetの反映SLAは定義しない |
| 認可範囲 | `issuers_allowed`はKeycloak issuer、`audience_required`は`fapi-demo-api`、`scopes_required`は`openid`（MUST） |
| sender constraint | `proof_of_possession_mtls: strict`（MUST） |
| claim由来header | `X-Demo-Department`と`X-Demo-Route`を検証済みclaimから設定し、client供給の値を上書きする（MUST） |
| certificateの転送 | `tls-metadata-headers`で`inject_client_cert_details: true`とし、URLエンコードしたPEMをUpstreamへ転送する（MUST） |
| 資格情報の除去 | `Cookie`と、client供給の`X-Fapi-*`をUpstreamへ送らない（MUST）。`Authorization`はUpstreamの再検証のために転送してよい（MAY） |
| Upstreamへの接続 | API Gateway upstream certでmTLS接続し、Upstream APIのserver certificateを検証する（MUST） |
| TLS | TLS 1.2以上、BCP195推奨のcipher suite（MUST） |
| error | `401`、`403`で`WWW-Authenticate`を返す（MUST） |

`tls-handshake-modifier`、`tls-metadata-headers`、`proof_of_possession_mtls`の挙動は`kong-ee` masterのsourceで確認した。3.16.0.0のschemaで同じ挙動であることを、実装時に確認すること（MUST）。

## Upstream API contract

v1の「PoP verifier API contract」を次のように変更する。

1. TLS client certificateが**API Gateway upstream cert**であることを要求する（MUST）。それ以外の接続は拒否する。
2. JWT署名をKeycloak JWKSで検証し、`iss`、`aud=fapi-demo-api`、`exp`、`nbf`、必須scopeを検証する（MUST）。algorithmはPS256だけを許可する。
3. `cnf.x5t#S256`を要求する（MUST）。
4. API Gatewayが転送した`X-Client-Cert`をURLデコードし、そのSHA-256 thumbprintを`cnf.x5t#S256`とconstant-time比較する（MUST）。
5. 不一致または欠落の場合は`401 invalid_token`を返す（MUST）。
6. Route識別子は`azp`から導出する（MUST）。`X-Fapi-Route`などのheaderからは導出しない。

responseは、v1に次を加えてよい（MAY）: `azp`、API Gatewayが検証したTLS peer certificateのthumbprint、Upstream自身による再検証結果のboolean。

## UI requirements

v1の「UI requirements」を継続する。表示する「TLS peer certificate thumbprint」は、**API Gatewayが受け取った3rd Party Gatewayのcertificate**のthumbprintとする。UIは、構成図上でどの区間の証跡かを示すラベルを表示すること（SHOULD）。

## Delivery and automation requirements

v1の「Infrastructure as code」「GHCR」を継続し、次を追加する。

- Terraformは、API Gateway用と3rd Party Gateway用の2つのKonnect control planeと、それぞれのdata plane certificateを管理すること（MUST）。既存のcontrol planeは、API Gateway用として再利用する（SHOULD）。
- decK stateは、Gatewayごとに別ファイルとすること（MUST、例: `kong/api-gateway.yaml`、`kong/third-party-gateway.yaml`）。`make deck-diff`と`make deck-sync`は、対象Gatewayを明示して実行できること（MUST）。
- `make validate`は、両方のdecK stateを検証すること（MUST）。live systemは変更しないこと（MUST NOT）。
- GitHub Actionsで`make validate`と`make test`をPRのstatus checkとして実行すること（SHOULD）。

## Observability and evidence

v1の必須evidenceを継続し、次を追加する。

- 3rd Party GatewayがAPI Gatewayへ提示したcertificateのthumbprintが、Keycloakでtoken取得時に提示したcertificateのthumbprint、およびtokenの`cnf.x5t#S256`と一致する。
- API Gatewayのintrospection requestが、API Gateway introspection certで認証されている。
- reset後に新しい認可フローで次ケースを実行できる。失効token拒否を追加で検証した場合だけ、その証跡とcache条件を説明する。
- PAR/token/refresh/revokeとmetadata取得ごとに、AS側で受け取ったcertのthumbprint・検証結果を示す（生の資格情報は記録しない）。
- 3rd Party GatewayからAPI Gatewayへのrequestが、Authorization headerだけでtokenを運んでいる。

## Acceptance scenarios

v1のシナリオIDは、実行主体を3rd Party Gatewayへ読み替えて継続する。ただしlogoutは上記のデモreset条件で上書きし、全v1シナリオ合格を要求しない。その他の対象IDは次のとおり（`A-PAR-01`、`B-PAR-01`、`B-PKJ-01`、`CLAIM-01`、`LOGOUT-A-01`、`LOGOUT-B-01`、`SWITCH-01`、`A-CERT-01`、`A-CERT-02`、`B-AUD-01`、`B-JTI-01`、`B-SPOOF-01`、`B-CERT-01`、`HEADER-01`、`LEAK-01`）。v1の`A-POP-01`、`B-POP-01`、`POP-01`、`POP-02`は、次の表のシナリオで置き換える。

### Positive scenarios

| ID | Scenario | Pass condition |
|---|---|---|
| A-E2E-01 | Route Aで、loginからUpstream API呼び出しまで | UIに、`azp=third-party-fapi-mtls`とbinding一致が表示される |
| B-E2E-01 | Route Bで、loginからUpstream API呼び出しまで | UIに、`azp=third-party-fapi-pkj-mtls`とbinding一致が表示される |
| A-CNF-01 | Route Aのcertificate一貫性 | Keycloakでの提示cert、`cnf.x5t#S256`、API Gatewayでのpeer certのthumbprintが一致する |
| B-CNF-01 | Route Bのcertificate一貫性 | 同上（Route B TLS cert） |
| PAR-01 | PARの強制 | authorization requestより前にPARが行われる |
| PAR-02 | authorization endpointへのparameter | redirect URLのqueryが`client_id`と`request_uri`だけ。`nonce`は64文字以下 |
| PKCE-01 | PKCE | PAR bodyに`code_challenge_method=S256`があり、challengeがrequestごとに異なる |
| META-01 | issuerの一致 | 設定したissuerと、discoveryの`issuer`が一致する |
| META-02 | endpointの一致 | 3rd Party Gatewayの静的endpoint設定と、discoveryの値（`mtls_endpoint_aliases`を含む）が一致する |
| RT-01 | refresh | access tokenの期限切れ後に、同じcertificateでrefreshが成功する |
| RT-ROT-01 | refresh token rotation | Keycloakでrotationを有効にしたとき、新しいrefresh tokenで次のrefreshが成功する |
| RS-VALID-01 | introspection | API Gatewayが、API Gateway introspection certでintrospectionを行う |
| RS-INT-AUD-02 | 両Routeのintrospection audience | 両Routeのtokenが`aud`に`fapi-demo-api`と`api-gateway-introspection`を持ち、専用clientでのintrospectionが`active: true`と必要なclaimを返す |
| AS-MTLS-OBS-01 | WP5冒頭のAS peer観測spike | test-only Keycloak observerで実peer・chain検査・相関を取得。certなし対照/未信頼・期限切れTLS拒否とstock PAR/revoke claimを確認。公開設定でstockを起動する隔離fixtureは[peer証跡契約](third-party-as-peer-evidence.md)に従う。不成立なら本体実装前にneeds-design |
| B-TRANSPORT-01 | Route Bの全AS back-channel | PAR/token/refresh/revokeのすべてでRoute B certを提示し、AS側で検証されたことを確認。OAuth client認証はPKJWT。server certificateも検証する |
| AS-META-MTLS-01 | 両Routeのmetadata取得 | cold cacheのdiscovery/JWKS、bridgeの独自discovery、background/JWKS threadで専用metadata cert提示・検証を確認する。未知のAS呼出しは拒否する |
| AS-TRANSPORT-GUARD-01 | transportの境界検査 | 未知endpoint/HTTP/redirect、context/署名不足、conflicting cert、自動POST再送（fresh assertionでも拒否）をfail closed。異なるtokenのrefresh/access revokeは両方許可。A/B同時実行でもidentityが分離する（DP0 fixture） |
| AS-TRANSPORT-LIFECYCLE-01 | transportのlifecycle | Gateway別実ロード/未ロード・未設定guardを確認。transportだけ/両plugin欠落でpreflightがfailし、通常入口/UI閉鎖・Route A metadata未送信を確認。configure前/invalid/nilで対象通信を拒否。同一再通知はidempotent、変更はrestartで反映。metadata background/threadと他pluginへの影響を検証する（DP0 fixture） |
| RESET-01 | 次のデモケースへ切り替え | Route cookieとSSOをresetし、別Route・別userで新しい認可フローと期待する`azp`/claimを確認する。手動reset手順でも可 |
| HDR-01 | tokenの送信方法 | 3rd Party GatewayからAPI Gatewayへのrequestで、tokenがAuthorization headerだけにある |
| TLS-01 | TLS検証 | 3rd Party GatewayとAPI Gatewayの全outbound接続で、server certificateを検証している |
| TLS-RS-01 | API GatewayのTLS | TLS 1.1以下と非推奨cipher suiteでの接続が失敗する |

### Negative scenarios

| ID | Scenario | Expected result |
|---|---|---|
| POP-01 | client certificateなしで、bound tokenをAPI Gatewayへ送る | API Gatewayが`401`を返す |
| POP-02 | 別Routeのcertificateで、bound tokenをAPI Gatewayへ送る | API Gatewayが`401`を返す |
| POP-03 | 登録済みRoute certへ束縛したtokenを、その`cnf`と一致しない開発CA外の自己署名certificateで送る | API Gatewayがbinding不一致を理由に`401`を返す。CA外であることだけを拒否理由にしない |
| RS-QUERY-01 | tokenをquery parameterで送る | API Gatewayが`401`を返す |
| RS-AUD-01 | `aud`に`fapi-demo-api`を含まないtoken | API Gatewayが`401`または`403`を返す |
| RS-INT-AUD-01 | `fapi-demo-api`は含むが、`api-gateway-introspection`を含まない有効なtokenを専用clientでintrospectionする | Keycloakが`active: false`を返す。audience checkの回避設定を使わない |
| RS-SCOPE-01 | 必須scopeを欠くtoken | API Gatewayが`403`を返す |
| RS-REVOKE-01 | 有効なsessionを維持し、両Routeのaccess tokenをそれぞれ単独でrevokeして、正しいcertificateで再送する | revoke前は`active: true`とAPI成功、後は`active: false`とAPI `401`。JWT署名・`exp`・bindingが有効でも通過しない。cache条件を記録し、拒否を確認する（追加説明用・DoD対象外） |
| REVOKE-RS-01 | 両Routeのlogout前後で、同じaccess tokenを正しいcertificateで再送する | logout前は`active: true`とAPI成功、後は`active: false`とAPI `401`。cache条件を記録し、拒否を確認する（追加説明用・DoD対象外）。HTTP `200`だけでは合格にしない |
| ERR-01 | 上記の拒否応答 | `WWW-Authenticate`にRFC 6750のerrorを含む |
| HEADER-CERT-01 | clientが`X-Client-Cert`を偽装して送る | Upstream APIは偽の値を受け取らない |
| UPSTREAM-01 | API Gatewayを経由せずにUpstream APIを呼ぶ | Upstream APIがTLS接続または`401`で拒否する |
| ISS-01 | 認可レスポンスの`iss`を別の値に改変する | 3rd Party Gatewayが拒否する |
| ISS-02 | 認可レスポンスから`iss`を除去する | 完全適合へ向けた将来シナリオ。guard追加時に拒否を確認する。今回のDoD対象外 |
| B-AUD-02 | Route BのPARとrevocationのPKJWT（正常形式の確認） | `aud`が配列ではなくissuer文字列であること。DP0で確定した補完実装を対象とする |
| REDIR-01 | login/logout後のredirect先を外部URLへ誘導する | 固定のredirect URI以外へは遷移しない |
| ALG-01 | ID tokenとaccess tokenのalgorithm | すべてPS256であること |
| CSRF-01 | cross-siteから認可の開始を誘発する | 将来の開始CSRF防御の検証シナリオ。今回のDoD対象外。安全性は未保証であり、対外説明では未対応とする |

## Definition of done

本節はv1のDefinition of doneを**置き換える**。

- DP0/ADR 0012のP0補完契約を独立レビュー・設計mergeし、設計PRへ反映する。合意前にWP5をreadyにしない。オフライン技術確認はlive受入の代わりにしない。
- A-E2E-01、B-E2E-01、A-CNF-01、B-CNF-01、B-TRANSPORT-01、AS-META-MTLS-01と、PKJWTの署名・audience・replay拒否、certなし/不一致拒否（POP-01〜03）が証跡付きで通る。
- 標準機能の追加価値（P1）の対象シナリオをDelivery planで列挙し、結果を記録する。新規customが必要な追加価値は設計へ戻して範囲を見直す。未実施をpassとせず、理由と顧客説明への影響を記録する。
- RESET-01が両Routeから通る。自動logoutまたは文書化した手動resetで次ケースを再現できる。LOGOUT-A/B-01とSWITCH-01はこの条件で判定する。
- 両Gatewayのsync前diffが意図したentityだけ、sync後diffが無い。clean checkoutの起動・操作手順で両Routeを再現できる。適用は別途live承認後に行う。
- 対外説明で、標準機能・custom補完・未対応・未検証を区別する。完全適合、認定、本番運用可能性、未検証の失効保証を主張しない。
- CSRF-01、ISS-02、RS-REVOKE-01、REVOKE-RS-01、DPoPは、今回の必須合格条件ではない。これはデモ範囲の決定であり、それらの安全性や仕様適合を認定するものではない。

## Out of scope / 追加候補

- 本番想定のFAPI 2.0完全適合、認定試験、鍵更新・HA・大規模負荷・監視等のproduction hardening
- 開始CSRFの追加防御、`iss`欠落guard、個別access/refresh token失効保証と反映SLA
- DPoPの実装（追加候補として設計調査DP1を行い、着手は別途合意）
- Dynamic Client Registration、Kong以外の3rd Party client実装、consumer単位のrate limit/認可ポリシー
- ASのbrowser入口とserver入口を分離したmTLS強制listener（現構成はcertがあれば検証する`request`モード）

## Workflow diagrams

`workflows/`配下の次の図を、本要件に合わせて更新する。図は設計上のworkflowを示すものであり、実装状況を示すものではない。

| Diagram | Source | 内容 |
|---|---|---|
| Architecture | [JSON](workflows/third-party-architecture.architecture.json) / [HTML](workflows/third-party-architecture.architecture.html) | 組織境界、2つのGatewayとcontrol plane、接続ごとのcertificate |
| Route A | [JSON](workflows/route-a-mtls.workflow.json) / [HTML](workflows/route-a-mtls.workflow.html) | 3rd Party GatewayのRoute Aと、API Gatewayでの検証 |
| Route B | [JSON](workflows/route-b-pkj-mtls.workflow.json) / [HTML](workflows/route-b-pkj-mtls.workflow.html) | 3rd Party GatewayのRoute Bと、API Gatewayでの検証 |
| Logout | [JSON](workflows/logout.workflow.json) / [HTML](workflows/logout.workflow.html) | stock logoutの通常経路と、次ケースへ進むためのデモreset |

![3rd Party経由構成のarchitecture](workflows/third-party-architecture.architecture.png)

![Route A](workflows/route-a-mtls.workflow.png)

![Route B](workflows/route-b-pkj-mtls.workflow.png)

![Logout](workflows/logout.workflow.png)

GitHub Pagesの公開版は、本設計PRのmerge後に更新する。それまでは、Pagesのリンクがv1の図を指す。

## Primary sources

- [FAPI 2.0 Security Profile — Final](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 9207: OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [RFC 7662: OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [Keycloak FAPI support](https://www.keycloak.org/securing-apps/oidc-layers#_fapi-support)
