# Keycloak側AS mTLS peer証跡（test-only設計）

## 方式と状態

2026-10-02、OpusレビューOM-01への設計補強。**方式は固定したが、build・実行・live成立確認は未実施**。WP5冒頭の`AS-MTLS-OBS-01`で成立を確認してからtransport本体実装へ進む。[DP0契約](third-party-as-mtls-transport.md)と[Delivery plan](third-party-delivery-plan.md)を併用する。

一次取得元は**Keycloak 26.7.4のtest-only source-instrumented image内のrequest observer**とする。test AS、Gateway option log、TLS終端proxy、完全certificateのaccess logは代替にしない。通常デモimage/起動手順にはobserverを組み込まない。これはお客様向け認証機能の追加ではなく、受入試験のための計測コードである。実装・test起動のlive承認は別途必要。

### 固定版sourceで確認した観測点

[TransactionalSessionHandler](https://github.com/keycloak/keycloak/blob/26.7.4/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/TransactionalSessionHandler.java)の`handle`で、currentSessionを取得・thread contextへ設定した後、`super.handle`の前へtest-only observer呼出しを追加する。同request内でsub-resource解決により複数回呼ばれるので、request-localな観測済みflagで1 HTTP requestにつき1行にする。[HandlerChainCustomizer](https://github.com/keycloak/keycloak/blob/26.7.4/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/KeycloakHandlerChainCustomizer.java)のalternate invocation handlerがこのclassを選ぶことをsourceで確認した。全inventoryへの実際の到達はspikeで検証する。

observerは`currentSession.getContext().getHttpRequest()`からmethod/path/header/peer chainを読む。[QuarkusHttpRequest](https://github.com/keycloak/keycloak/blob/26.7.4/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/QuarkusHttpRequest.java)の`getClientCertificateChain`はTLS `SSLSession`のpeer certificateを取得し、peer未認証時はnullになる。proxy certificate headerを読まない。このsource確認はtest用patchの実行可能性の見立てであり、実行成功の証明ではない。

## Test imageとobserverの制約

- public tag `26.7.4`をcommit SHAへ解決してpinする。差分は上記の観測呼出しとobserver helperに限定する。OAuth/authentication、TLS/truststore、endpoint、bodyを変更しない。build元commit、patch SHA、artifact/image digest、依存版を証跡に残し、通常のKeycloak imageと計測用imageを混同しない。
- test-onlyフラグ`FAPI_DEMO_AS_PEER_OBSERVER=true`で明示起動し、false時には観測しない。通常デモは標準imageを使う。同じrealm/TLS設定の標準imageでもpositive flowを再実行し、計測imageだけの成功をデモ完成にしない。
- 計測対象はDP0のAS inventoryのmethod/pathだけ。browser authorization/logout、admin、未知pathは記録しない。body/query/full headers/Subject DN/raw JWT/token/code/cookie/key/完全cert/TLS session keyを読み出してlogへ出さない。PEMを生成しない。
- leaf certificate DERをmemory内だけでSHA-256化し、local evidenceへbase64url thumbprintを記録する。PRは先頭12文字だけ。同じ開発CAをtrust anchorに、peer chainのPKIX・有効期間・clientAuth EKUもtest helperで検査し、結果をbooleanで記す。TLS peer取得とPKIX再検査は別項目にする。
- 計測の例外や欠落はsanitizedな`observation_error`としてtestを失敗させる。認証処理を成功へ変更せず、通常endpointへ新しいAPIを追加しない。sub-resourceの重複flagはrequest context内だけに置き、worker-global/session-globalへcertや相関状態を置かない。

## 相関方法（時刻だけの推測をしない）

transportのtest用設定`evidence_correlation_enabled: true`と、上記AS observerフラグを同じ受入profileで使う。既定はfalse。送信境界で各network operationへrandom 16-byteの小文字hex（32桁）を生成し、`X-Fapi-Demo-Observation-ID`を設定する。これをevidenceの`request_id`とする。credentialではなく、認証・Route・cert選択には使わない。

caller供給の同名headerはcase-insensitiveに除去してからserver生成値へ置き換える（false時は除去だけ）。metadataのbackground/threadにも毎回新しいIDを作る。AS observerは厳密な32桁hexだけを受け取り、method/pathと合わせて照合する。malformed/欠落IDはその試験のfailで、任意文字列をlogへ出さない。clientが選んだIDだけからTLS identityを認定しない。

HTTP処理直前のAS側記録は、ID、UTC時刻、method、queryなしpath、peer cert有無、leaf thumbprint、`peer_chain_pkix_valid`、error種別だけ。HTTP status/OAuth結果は同じIDのGateway側operation結果とjoinする。joinは1:1が必須。欠落/重複/不一致はfail。network送信前の拒否はAS行なしを期待し、`not_sent`と記録する。

`tls_peer_verified`をpeer certがあるだけでtrueにしない。次の全条件でのみ成功証跡とする: ASで実peerを取得、helperでPKIX/期限/EKU成功、Keycloak listener/truststoreの固定receiptあり、同構成の未信頼・期限切れcertをTLSで拒否するnegative fixtureがpass。PKIX helperはTLS実装のverify flagそのものではないので、`verification_basis`に`peer_observed+pkix+listener_negative`を記す。TLS negativeが成立しなければ完了しない。

## AS-MTLS-OBS-01: WP5冒頭のspikeゲート

1. observer imageをbuildし、**本体pluginを実装する前はdirect TLS harness**が同じ規則のIDを付け、inventory全GET/POSTでobserverが1回だけ到達することを検証する。HTTP 4xxでもTLS観測は確認できるがOAuth成功とは数えない。discovery/JWKSはmetadata cert、PAR/token/refresh/revokeはRoute cert。OAuth成功/拒否のHTTP statusとTLS peer観測を分ける。
2. spikeではharnessの各endpoint/Route identityとrequest IDを1:1 joinし、A/B同時実行でも取り違えなしを確認する。本体plugin実装後はAS-META-MTLS-01/AS-TRANSPORT-LIFECYCLE-01でstock/bridge経由、cold/warm/background/threadも確認する。warm no-fetchはskipでありmTLS passにしない。
3. 同じ`request` listenerでcertなしGETを直接送る対照試験はHTTP到達・`peer_cert_present=false`を期待する。これはmTLS成功ではなく、全入口強制がないことの証跡。
4. 未信頼/期限切れcertはdirect TLS harnessから提示し、TLS handshake拒否・AS HTTP観測行なしを確認する。pluginが送信前に拒否するfixtureと分ける。observerがHTTP到達を記録したら、verified=trueにせずneeds-design。
5. server CA/SAN不正をclient側で拒否、AS側正常peerとtoken binding/PKJWT受入をそれぞれ記録する。B-JTI-01のdirect negativeはharnessが同じ規則のIDを生成し、通常pluginの再送抑止と混同しない。
6. spike用fixtureはexact Kong imageのstock PAR/revoke生成処理を実署名で呼び出し（HTTP boundaryだけtest harnessで受ける）、claim検査とASへのcontrolled requestを行う。raw assertionをlog/永続化しない。stock PAR/revoke assertionの実署名とclaim（issuer文字列aud、PS256、`0 < exp-iat <= 60`、残存TTL >= 5秒）をsanitizedに検査する。claim不適合は本体実装前にDesign ownerへ戻す。

### 手順6のstock生成経路（OMD-02、test-only fixture）

private module関数を直接呼ばず、**通常デモとは隔離したexact Kong 3.16.0.0のOIDC Route B fixture**を公開plugin設定で起動する。v1相当の`authorization_code + session`、既存bridgeのheader mode + stock token/refresh `tls_client_auth`でtokenを取得し、stock logoutからrevokeを起動する。新transport/delegateの本体実装は前提にしない。fixtureはtest用network/利用者承認済みtest入口だけに置き、通常3rd Party/APIのpluginロード契約やデモ入口ゲートを緩めない。

`H = https://as-spike-harness:9443`をtest内の固定宛先とする。変更するendpointはPAR/revokeだけ。issuer `I`、authorization/token/JWKS/end-session、client ID、signing key、Route B cert、JWT audienceは変更しない。

| stock OIDC公開設定 | spike fixtureの値 / 目的 |
|---|---|
| `pushed_authorization_request_endpoint` | `H/par` |
| `pushed_authorization_request_endpoint_auth_method` | `private_key_jwt` |
| `revocation_endpoint` / `mtls_revocation_endpoint` | 両方`H/revoke`。元のaliasが残ってharnessを迂回しない |
| `revocation_endpoint_auth_method` | `private_key_jwt` |
| `logout_revoke` | `true` |
| `logout_revoke_access_token` / `logout_revoke_refresh_token` | 両方`true`。sessionに各tokenがあることを確認し、各revokeを記録 |

- PAR: browserの新規認可でstockが`H/par`へ送ったformをharnessがmemory内だけで検査する。同じform/assertionを変更・再署名せず、Route B cert + server CA/SAN検証でobserver Keycloakの`O/ext/par/request`へ1回だけ送る。実ASのPAR応答をmemory内でstockへ返し、正常な認可/code exchangeでsessionを作る。OAuth成功・sessionに必要tokenがあることを確認後、stock logoutを呼び、`H/revoke`で同じ手順を行う。HTTP 4xx/TLS failure/timeout時は成功に偽装せずfail/needs-designとする。
- harnessはTLS serverとして開発CA/SANを検証できる設定にする。stock→harnessはclaim採取用のHTTPS hopであり、PKJWT branchにclient certがないことを**mTLS成功として数えない**。AS peer証跡はharness→実KeycloakのRoute B mTLS hopでのみ取得し、stockの実AS直結mTLSを証明したとはしない。新transport経由の証明は本体後のB-TRANSPORT-01で行う。
- 最終AS送信でharnessが32桁IDを生成し、stock生成経路・endpoint kind・sanitized claimとobserver行を1:1 joinする。同じassertionを再送/再署名しない。harness側もredirect/自動POST retry/connection・TLS session reuseを無効にする。重複受信時はmemory内のdigestで拒否し、2種類のtoken revokeは別operationとする。request/response body、JWT、token、cookie、code、jtiはlog/永続化しない。
- これは**claim生成を採取する隔離fixtureの一時relay**であり、停止条件が禁止する「別AS/proxyのpeerを実Keycloakのpeer証跡として代用」「通常デモの通信をproxyへ迂回」とは別である。AS一次観測は実Keycloak observerのまま、通常デモへharnessを組み込まない。

公開設定名はcached exact imageのschemaを依存mock付きでread-only評価し、8項目の存在と2つのauth methodの`private_key_jwt`許容、logout flagのshapeを確認した（`.generated/opus-delta-followups-20261002/schema-shape-receipt.json`）。これはschema validation・endpoint選択・実署名/flowの成功ではない。最新版[OIDC設定reference](https://developer.konghq.com/plugins/openid-connect/reference/)と[stock session logout例](https://developer.konghq.com/plugins/openid-connect/examples/logout/)も参照するが、固定imageの実挙動はspikeで検証する。harnessへの到達、issuer audience、PAR応答からのsession成立、各revokeの起動が不成立なら、private API呼出しやclaim書換えで回避せずDesign ownerへ戻す。

**停止条件**: hook/build/peer取得/chain検査/correlation/negative TLS/claimのいずれかが不成立なら、WP5は本体実装前にneeds-design。観測方式はWorkerが選び直さない。Design ownerがcost/scopeを再提案する。HTTP option log、別AS、追加proxy、certificate headerの偽装、certなし再送への置換を禁止する。

証跡は`.generated/evidence/AS-MTLS-OBS-01.json`と、各operationの既存scenario evidenceへjoinする。source確認receiptは`.generated/opus-review-fixes-20261002/keycloak-source-receipt.json`（public source、Git管理外）。[26.7.4 mutual TLS guide](https://github.com/keycloak/keycloak/blob/26.7.4/docs/guides/server/mutual-tls.adoc)の`request`はcertなし接続も許容する。実際のTLS挙動は上のnegativeで確認する。
