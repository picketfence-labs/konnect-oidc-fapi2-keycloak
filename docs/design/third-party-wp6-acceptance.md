# WP6 UI・切替・再現受入表

## 現在地

WP6は顧客向けデモのUI表示、logout/reset後のroute切替、clean checkout手順を仕上げるpackageです。WP1～WP5の受入結果を再実行せず再利用します。WP5のP0/P1/D判定と承認済みの未網羅範囲は[WP5受入表](third-party-wp5-acceptance.md)、顧客への説明は[デモ説明](third-party-demo-explainer.md)を正とします。

UIのNode単体検査はpassし、HTTPの静的previewでは初期画面とfragment除去を確認しました。通常HTTPフローで4回のlogout/resetとroute切替もpassしています。HTTPS result画面の実browser表示とsource-controlled Compose overrideを使うclean checkoutの起動は未実行です。この区分を通常routeのruntime受入と混同しません。UI previewとCompose configのsanitized review receiptはGit外に保存し、それぞれ`wp6-ui-root-review-20261005.json`（SHA-256 `57fb46d5e2409a2a2c685e19e5880a5d3ecaf0a12d29034403c83a55ca0055be`）、`wp6-native-compose-review-20261005.json`（SHA-256 `15afcf69404671eacc7f5323bad1b46de45cf6feb6bdc446c866ca778786da37`）です。Compose receiptはstatic_not_runtimeです。

## WP6 acceptance ID

| 受入ID | 実装・操作 | 検証層・結果 | 既存証跡と限界 |
|---|---|---|---|
| A/B-E2E-01 | UIはAPI responseのallowlistを表示。Route A/Bは既存通常flowで確認 | normal HTTP flow pass。HTTPSのresult画面はnot_run | `wp5-normal-flow-route_a.json` SHA-256 `0050094f0f7c31b08cbbd433bbf58f771a1f0c046b23173e5085ac0648a0286d`、`wp5-normal-flow-transport_route_b.json` SHA-256 `4340fad6e39b197c8d5106b28a199af64a6be2a6394298197ca4483ac2c82bd8`。API/Upstream成功の証跡で、今回のHTTPS UI renderingは証明しない |
| CLAIM-01 | department、logical route、azpから固定Route/auth methodを表示 | UI projector unit pass。A/B runtime claims pass | 表示値はAPI responseの短い文字列と固定azp mappingだけ。画面のHTTPS実表示はnot_run |
| HEADER-01 | claimとUpstream header、spoof結果を表示 | projector unit pass。通常A/Bでclaim/headerとspoof上書きを確認 | WP5通常A/B証跡を再利用。個別header matrixはWP5受入表の範囲を維持 |
| LEAK-01 | raw JSONを画面に出さず、token/cookie/assertion等を表示・保存しない。login URL fragmentを初期化時に除去 | allowlist unit pass。HTTP previewのfragment sentinel除去pass。HTTPS result画面はnot_run | projectorは表示フィールドのみを返し、thumbprintは先頭12文字。WP5 secret scan/response evidenceはWP5受入表を参照 |
| ALG-01 | azpからclient認証方式を固定表示し、署名検証booleanを表示 | projector unit pass。署名/algorithmのruntime証跡はWP5受入表を再利用 | `token_signature_verified=true`は署名検証の成功を示すだけで、JWT `alg`を示さない。UIはalgを推定・表示しない |
| RESET-01 | 同じcookie jarでRoute A/Bを交互に実行し、各logout後に対象Routeを再確認 | normal HTTP flow pass: A(sales) → B(engineering) → A(sales) → B(engineering)、4/4 | Git外 `.generated/evidence/wp6-reset-review-1791160856983744000.json` SHA-256 `00a7a916ab41194477d5bc4d493054116a1d0074c66c53906b2bd305e5a0c2b4`、mode 0600。各開始302、Keycloak login submission 1回、期待azp/claim、API 200、logout完了、対象route cookie activeなし。browser UIの実演ではない |
| LOGOUT-A/B-01 | どちらのRouteからもstock logoutへ進む | normal HTTP flow pass。Route A/Bそれぞれ2回 | RESET-01証跡とWP5通常A/B証跡を再利用。logout成功は個別token失効SLAを意味しない |
| SWITCH-01 | logout後に別Route・別demo userでfresh loginを行う | normal HTTP flow pass: A→B、B→Aを確認 | RESET-01証跡を再利用。SSO再利用なしは各flowのlogin form submissionで確認。HTTPS画面とclean checkoutでの切替はnot_run |

## UI表示契約

- client認証方式は`azp`の固定mappingから選び、responseの`client_authentication`や呼出し側headerを使わない。
- `token_certificate_thumbprint`と`forwarded_client_certificate_thumbprint`だけを3rd Party→API Gateway間のthumbprintとして表示し、各値は先頭12文字に制限する。
- `api_gateway_tls_peer_certificate_thumbprint`はAPI Gateway→Upstream verifier間の証跡なのでUIの3rd Party→API表示に含めない。
- UIはresponse全体をDOM、storage、logへ書かず、API responseの明示的allowlistだけを`textContent`へ表示する。
- UI署名欄は`token_signature_verified`のbooleanだけを示す。algorithmの根拠は隔離・runtime証跡を使う。

## Clean checkout再現の状態

`docker-compose.demo-native.yml`はAPI Gatewayとverifierにdigest固定済みの公開amd64 imageを使い、third-party Data PlaneにKong 3.16.0.0のnative arm64 baseとsource-controlled pluginのread-only mountを使います。image buildやmulti-architecture publishは行いません。対象は受入済みの既存2 Control Planeを再利用したローカルruntimeです。Compose 5.2.0のstatic configでは5 service、全build field除去、TP native platform、plugin read-only mount、既定入口closedを確認しました。

clean checkoutでは`.env`、既存2 CP/DPのruntime inputs、開発用PKI・Keycloak realm/credentialsをGit外の許可されたbackupから復元します。Keycloakの既存DBを再利用する場合は、そのDBとrealm/usersに一致する`.generated`入力を一緒に使います。新しいdemoを初期化するときにだけ`make generate-dev-assets`を実行し、既存realmのpasswordと置き換えません。新規Konnect環境の作成・bootstrap・migrationはWP6に含みません。新環境にはTerraform、schema、foundation、runtimeの各previewと別のレビューが必要です。

現時点でoverrideのHTTP compose config確認までは行っています。fresh checkoutからのimage pull、Data Plane起動、readiness、supervisor、HTTPS画面、A/Bブラウザーフローはnot_runであり、利用者のレビュー後に代表実行します。既存2 CP再利用時は、APIの既知`openid-connect.config.cache_tokens_salt` 1 updateとthird-party diff 0を期待します。この既知API差分に対する追加syncは行いません。想定外の差分があればsyncせず、人が内容をレビューします。

## 明示する未対応・既知差分

- RFC 9126のRoute B PKJWT PARにおけるform `client_id`省略は既知仕様gapです。stock本文を変更せず、適合を主張しません。
- Keycloak 26.7.4のrevocation metadata URLは静的back-channel URLと文字列一致しません。[ADR 0021](../decisions/0021-wp5-revocation-metadata-gap.md)に従い現構成を維持し、META-02完全一致はpassにしません。
- metadataの差分受入、重い網羅検証縮小、`iss`欠落guard、追加認可開始CSRF防御、DPoP、厳密な個別失効SLAは今回の対象外または未対応です。[Conformance表](third-party-fapi2-conformance.md)と[WP5受入表](third-party-wp5-acceptance.md)に既存のP0/P1/D・F/N/A・未網羅理由を残します。
