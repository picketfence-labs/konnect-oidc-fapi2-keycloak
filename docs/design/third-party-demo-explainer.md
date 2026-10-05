# お客様向けデモ: 対応範囲と追加実装

## 最初に伝えること

このデモは、FAPI 2.0対応の検討材料として、3rd Partyを含む構成でKongの主要機能を実演するものです。完全適合・認定済み・そのまま本番投入可能という説明はしません。

受け取った顧客要件をなるべくKong標準機能で実装し、その環境をデモすることをゴールとします。2026-10-04に確認した固定版Route BのPKJWT PARのform client_id省略は、RFC9126/FAPI 2.0適合上のgapとして開示します。stock本文へのID補完は行わず、実フローの動作確認を進めます。[既知gapの記録](third-party-fapi2-conformance.md#既知のparギャップ2026-10-04)

**Route A/Bの通常フローとreset/switchは確認済みです。** UIの表示allowlist、azp固定mapping、thumbprint先頭12文字、fragment除去は静的検証しました。初期UIとfragment除去のHTTP previewも確認しましたが、HTTPS result画面の実browser表示とclean checkoutからのoverride再現は未確認です。確認層と証跡は[WP6受入表](third-party-wp6-acceptance.md)に記録します。WP5の隔離試験・通常統合・受入範囲は[WP5受入表](third-party-wp5-acceptance.md)を参照してください。

## お客様の要望と今回の優先順位

| 要望 | 今回の扱い | デモで見るもの |
|---|---|---|
| mTLSは必須。特に3rd Partyとの通信 | 最優先。3rd Party → AS・APIのサーバー間通信をmTLSにする | 接続ごとのpeer cert、tokenに束縛されたcertとの一致、APIでのcertなし/不一致拒否 |
| private_key_jwtも必要 | Route Bで実演。mTLSと同時に使う | PKJWTによるclient認証、mTLSによる通信、certificate-bound tokenによるAPI呼出し |
| DPoPもできるとベター | 追加候補。可否・工数を設計調査する | RS側の標準検証とclient側のproof生成の分担。今回の必須デモの完成を遅らせる前提にはしない |

## mTLS・private_key_jwt・token bindingの違い

- **mTLS transport**: 通信時にserverとclientがcertificateを提示・検証する仕組みです。
- **OAuth client認証**: ASが「どのアプリケーションか」を確認します。Route Aは`tls_client_auth`、Route Bは署名付きJWT（`private_key_jwt`）です。
- **certificate-bound token / PoP**: tokenを取得したcertificateと、API呼出しで提示するcertificateが一致することを確認します。tokenだけを持ち出しても使えないことを示します。

Route Bは「PKJWTを使うのでmTLSは不要」ではありません。PKJWTでアプリケーションを認証しながら、通信にはmTLSを使い、APIではcertificate bindingを検証します。FAPIはsender constraintにmTLSまたはDPoPを選べます。両方を実装しなければ一律に不適合という意味ではありません。[FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)

## 本来のFAPI対応と今回のデモ

| 機能・観点 | 本来のFAPI対応 | 今回のデモ | 標準機能 / 追加実装 |
|---|---|---|---|
| TLS・server certificate検証 | 安全なTLSとserver検証が必要 | 開発CAでserverを検証。browserはHTTPS、server間はmTLS | OIDC/core TLS設定。metadata取得は専用transport pluginで補完（DP0/ADR 0012） |
| mTLS client認証（Route A） | 認められるclient認証方式 | 採用 | client認証とcertはstock OIDCの`tls_client_auth`。送信境界guardとmetadata mTLSにはcustom transportが介在 |
| PKJWT client認証（Route B） | 認められるclient認証方式 | 採用。mTLS transportと併用 | PKJWT自体はstock対応。ただし同一requestでのmTLS併用はbridge等で補完 |
| AS全back-channelのmTLS | すべてのendpointへの一律mTLSはFAPIの一般要件とは別 | 顧客向け接続方針として採用。PAR/token/refresh/revoke、discovery/JWKSも対象 | token/refreshはbridge送信時delegate。PAR/revokeはstock PKJWT + transport、metadataも専用transportで補完（実装・隔離AS検証済み） |
| certificate-bound tokenの検証 | sender constraintを検証する | 両Routeで採用 | API側stock OIDC `proof_of_possession_mtls: strict` + certificate取得plugin。Upstream verifierはデモ固有の追加コード |
| PAR | 認可パラメーターをASへ事前登録する | 採用。browserへ認可パラメーターを直接並べない価値を説明 | stock OIDC + Keycloak設定。Route Bのtransport併用は追加補完 |
| PKCE S256・state | code flowとuser agentを保護する | 採用。認可コードの不正利用対策として説明 | stock OIDC + Keycloak設定 |
| issuer/audience/scope、header限定 | tokenの対象・認可範囲・受取方法を制限する | 採用。別APIのtokenや過剰な入力経路を受け付けない | stock OIDC設定。必要なaudience mapperはKeycloak |
| refresh/rotation | refreshと、新refresh tokenが返る場合の更新を扱う | stock機能を活用。rotationは設定切替で確認 | stock OIDC + Keycloak |
| tokenの失効状態 | RSは失効状態を含む有効性を確認する | introspection/active検査を採用。個別失効やlogout後の反映時間の厳密な保証は対象外 | stock OIDC。任意の失効テストの成功時だけ効果を説明 |
| 認可レスポンスのiss | RFC 9207に沿う検査が必要 | 提示されたissの不一致はstockで拒否。欠落拒否は未対応 | 完全対応へ進む場合はpre-function優先のcallback guardが必要 |
| 認可開始のCSRF防御 | 開始をCSRFから保護する必要がある | 明示UI操作・state/PKCEは使うが、開始CSRF防御済みとは説明しない | 完全対応へ進む場合は専用開始endpoint等を追加設計 |
| DPoP | 選択時はproof・nonce等も対応する | 追加候補。必須のmTLS経路とは分ける | RS側にstock検証機能。client側proof生成は別途必要性を調査 |
| logout/reset | デモreset自体は顧客FAPI要件ではない | 次のテストへ進めればよい。手動resetも許容 | stock logout、cookie破棄、Keycloak SSO終了。専用失効pluginは不要 |
| 本番・完全適合の評価 | AS/Client/RS全体、運用条件、全要件を確認する | 対象外 | 開発CA、ローカル環境、固定versionのデモ結果から本番適合を推論しない |

詳細な仕様行との対応は[要件対応表](third-party-fapi2-conformance.md)を参照します。表の機能数から「何％適合」とは計算しません。

Keycloak 26.7.4のdiscoveryはrevocation endpointにbrowser-facing hostを返し、Kongの明示的back-channel設定はcontainer-internal hostを使います。両方とも同じrealmとpathを指し、通常A/B logoutは成功していますが、metadata URLの文字列完全一致はしていません。この既知差分は[ADR 0021](../decisions/0021-wp5-revocation-metadata-gap.md)で受け入れています。revocation SLAやMETA-02完全一致を主張しません。

## 追加実装が必要なもの

### 今回の必須範囲

1. **Route BのPKJWT + mTLS併用**。stock PKJWTの存在だけでは、同じAS requestでclient certも送れることを保証しません。既存bridgeはtoken/refreshを補完しています。token/refreshは送信時署名へ限定し、PAR/revokeはstock PKJWTとtransport pluginを組み合わせています。隔離AS検証と承認範囲での通常Route A/B統合は完了しました。
2. **AS metadata取得のmTLS**。stock OIDCとbridgeのdiscovery/JWKS取得を専用metadata certificateで補完しています。隔離ASと通常metadata取得を確認しました。background/threadの全形態はWP5の合意範囲で網羅対象から除外し、未網羅として記録しています。
3. **UpstreamのPoP verifier**。転送されたcertificateとtokenを再検証し、UIへ安全な証跡を返すデモ用コードです。Kong標準機能とは区別します。

pre/post functionなら何でも補えるとは想定しません。ASへの送信処理は内部HTTP呼出しのため、単にrequest headerを追加するだけでPAR/revokeやmetadata取得のTLS設定を変えられるとは断定しません。[DP0契約](third-party-as-mtls-transport.md)で内部HTTP APIのmethod decoratorを選びました。これはworker-wideのcustom補完であり、標準設定や本番推奨方式とは説明しません。実TLS・Keycloak・lifecycleの受入は承認範囲で完了し、全background/thread形態の網羅はWP5の合意により省略しています。

### 受入試験だけの追加計測

ASが実際に受け取ったTLS peerの証跡は[test-only Keycloak observer](third-party-as-peer-evidence.md)で計測しました。26.7.4 public sourceへの観測専用patchと相関IDを使い、image build・direct TLS観測・再入計測は検証済みです。observerは通常デモへ入れません。通常デモは標準Keycloak imageで確認済みです。残るWP6の確認はHTTPS result画面のbrowser表示とclean checkoutからの起動です。

### 完全対応へ進む場合の追加候補

- iss欠落拒否: `pre-function`でcallbackをguardする方式を優先。利用できなければcustom pluginを検討。
- 開始CSRF防御: CSRF対策付きの認可開始endpointを追加設計。
- DPoP client: requestごとのproof生成、鍵管理、server nonce対応、replay対策を設計。RS側の検証だけではE2E対応になりません。[Kong公式DPoP説明](https://developer.konghq.com/plugins/openid-connect/#demonstrating-proof-of-possession-dpop)

## 説明上の注意

- Keycloakの同じlistenerへbrowserも接続するため、client certは`request`モードです。**実際のserver間通信はmTLSにする一方、ASの全入口でcertなしを拒否する構成ではありません**。これはAPI Gatewayのcert欠落拒否とは別の話です。[Keycloak 26.7.4設定](https://github.com/keycloak/keycloak/blob/26.7.4/docs/guides/server/mutual-tls.adoc)
- API側のtoken binding検証と、CA chainでのclient認証は別です。既定のAPI構成ではCA外という理由だけで拒否するのではなく、tokenとのbinding不一致を拒否します。
- logoutでUIが初期状態に戻ることやrevocationのHTTP 200は、持ち出した旧tokenが必ず使えないという証拠ではありません。
- 図は目標設計です。未実装・未検証を「標準機能だけで完全対応」「FAPI 2.0準拠済み」と説明しません。

## 実演の順序

1. 3rd Party / AS / API提供者の境界と、接続ごとのmTLS対象を図で説明する。
2. Route Aでlogin → token取得 → API成功。certificateとtoken bindingの一致を見せる。
3. Route Aをlogout/resetし、Route Bへ切替。同じmTLS経路でもclient認証をPKJWTへ変えられることを見せる。通常フローではA→B→A→Bの切替とdemo userごとの新規loginを確認済みです。
4. certなし・別certでAPIが拒否されることを見せる。
5. PAR、PKCE、issuer/audience/scope等の標準機能の価値を説明する。
6. 標準機能、今回のcustom補完、未対応の完全適合項目、DPoP追加候補を区別して締める。
