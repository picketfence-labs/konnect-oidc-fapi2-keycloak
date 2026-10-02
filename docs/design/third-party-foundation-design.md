# WP1: 2 Gateway基盤と段階別設定の詳細設計

2026-10-02、PR #13でレビューする設計補足。PR #5の認証・PoP・DP0方式を維持し、WP1が後続WPのhandlerやRoute設定なしで検証できる境界を定める。実装・schema登録・環境適用の結果ではない。[ADR 0013](../decisions/0013-work-package-schema-and-acceptance-boundaries.md)と[Luna移譲契約](third-party-luna-handoff.md)と一緒にレビューする。

## Terraformと接続先

既存CPをAPI用として残す。既存resource addressと秘密材料を移動しない。provider `konnect` 3.22系のローカルschemaで、CPの`config.control_plane_endpoint`/`telemetry_endpoint`がcomputed、DP certificateの`control_plane_id`と`cert`がrequiredであることを確認した。実環境のplanは別途必要。

| 用途 | 維持／追加するaddress | ローカルfile |
|---|---|---|
| API CP | 維持: `konnect_gateway_control_plane.demo` | — |
| API DP鍵・証明書 | 維持: `tls_private_key.dp`、`tls_self_signed_cert.dp`、`konnect_gateway_data_plane_client_certificate.dp` | 既存`infra/certs/tls.crt`、`tls.key`と`local_sensitive_file.dp_cert/dp_key` |
| 3rd Party CP | 追加: `konnect_gateway_control_plane.third_party` | — |
| 3rd Party DP鍵・証明書 | 追加: `tls_private_key.third_party_dp`、`tls_self_signed_cert.third_party_dp`、`konnect_gateway_data_plane_client_certificate.third_party_dp` | `infra/certs/third-party/tls.crt`、`tls.key`、追加`local_sensitive_file.third_party_dp_cert/third_party_dp_key` |

追加DP certificateは既存DPと同じECDSA P384、720時間、clientAuth用途で、別鍵・別CN・別CPへ登録する。API CPの名前、proxy_urls、labels、既存鍵のrenewal条件はWP1で変更しない。Terraformの`moved`/import/state操作を使って既存resourceを新CPへ付け替えない。

`third_party_control_plane_name`を追加し、defaultは`keycloak-fapi2-third-party-demo`。既存`control_plane_name`と等しい値を拒否する。追加output `gateway_targets`は、`api`と`third-party`それぞれに`control_plane_id`、`control_plane_name`、`control_plane_endpoint`、`telemetry_endpoint`を持つ。既存4 outputはAPIを指す互換出力として維持する。鍵・certificate・tokenをこのoutputへ追加しない。

runtime生成はAPI用`KONNECT_API_CP_HOST`/`KONNECT_API_TP_HOST`、3rd Party用`KONNECT_THIRD_PARTY_CP_HOST`/`KONNECT_THIRD_PARTY_TP_HOST`へ分ける。endpointのhttps schemeとpathを検査してhostnameを取り出し、各DPのcluster/telemetry設定へ対応付ける。空値、同一CP ID、曖昧なendpoint、旧単一CP変数へのfallbackを拒否する。Konnect region URLも同じtarget manifestへ固定する。

## PKIとidentity

DP→CP用の鍵と、AS/API/Upstream用の開発CA鍵を混用しない。新しい開発CA leafはRSA 3072 bit、30日以下、用途に合うEKUとSANを持つ。生成scriptは既存fileを上書きしない。更新には明示的な再生成操作と再previewが必要。

| identity | host側 `.generated/pki/` | container側 | 用途 |
|---|---|---|---|
| Route A/B | 既存`route-a.crt/.key`、`route-b.crt/.key` | `/etc/kong/fapi/route-a.crt/.key`、`route-b.crt/.key` | AS client認証／transport、3rd Party→API PoP。clientAuth |
| metadata | `third-party-metadata.crt/.key` | `/etc/kong/fapi/third-party-metadata.crt/.key` | discovery/JWKS専用。clientAuth。OAuth clientには登録しない |
| API server | `api-gateway.crt/.key` | `/etc/kong/fapi/api-gateway.crt/.key` | serverAuth、SAN `kong-api`、`localhost`、IP `127.0.0.1` |
| introspection | `api-introspection.crt/.key` | `/etc/kong/fapi/api-introspection.crt/.key` | `api-gateway-introspection`専用、clientAuth |
| API→Upstream | `api-upstream.crt/.key` | `/etc/kong/fapi/api-upstream.crt/.key` | clientAuth。Upstreamがこのleaf identityを固定して照合 |

新leafのCNは順に`third-party-metadata`、`kong-api`、`api-gateway-introspection`、`api-gateway-upstream`。既存Route certificateのCNはclient ID変更だけを理由に再生成しない。WP2が新client IDと既存certificate subjectを明示的に対応付ける。bridgeのPKJWT鍵`route-b-pkj.key`はtransportへ渡さない。

DP→CP certificateは各DPへ個別mountする。開発PKIも必要なfileだけをread-onlyでmountし、APIへRoute A/B・metadata・PKJWT秘密鍵を渡さず、3rd Partyへintrospection・API-upstream秘密鍵を渡さない。生成済みPKIディレクトリ全体の共通mountを最終構成で残さない。

Route UUIDは次の値を固定する。Certificate entity IDと混同しない。UUIDはnamespace URLによるUUIDv5で、生成元は`https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/routes/third-party/A`または`B`。

| 論理Route | Route UUID | client ID | path | Certificate ID（third-party CP内） |
|---|---|---|---|---|
| A | `754519ff-b0b9-5ed5-94c0-e453d260c6c4` | `third-party-fapi-mtls` | `/api/fapi/mtls` | `11111111-1111-4111-8111-111111111111` |
| B | `0f45debe-a3a6-5207-aea3-637227fb96f2` | `third-party-fapi-pkj-mtls` | `/api/fapi/pkj-mtls` | `22222222-2222-4222-8222-222222222222` |

APIの新introspection Certificate IDは`44444444-4444-4444-8444-444444444444`、API-upstreamは`55555555-5555-4555-8555-555555555555`。API基盤用CA entityは`77777777-7777-4777-8777-777777777777`、third-party側CAは既存と同じ`33333333-3333-4333-8333-333333333333`を新CP内で使う。API用CAは既存v1 CA entityへタグを付け足さず追加する。同じ開発CAの公開証明書でもCP内entityを区別する。API server certificateはNGINX listenerのfile設定であり、これらclient Certificate entityの代用にしない。

## foundationとruntimeのdecK state

WP1が最終Route設定の空の代用品をsyncすると、既存v1の`fapi2-demo` entityを削除し得る。schema準備だけではWP3/WP5への依存を解消できないため、別file・別管理範囲に分ける。

| 段階 | file（開発時に作成） | `_info.select_tags` | owner／内容 |
|---|---|---|---|
| API foundation | `kong/foundation/api.yaml` | `[fapi2-demo, fapi2-foundation]` | WP1。新CA、introspection/upstream Certificate。Service/Route/OIDC/custom entityなし |
| 3rd Party foundation | `kong/foundation/third-party.yaml` | `[fapi2-demo, fapi2-foundation]` | WP1。Route A/B Certificate、CA、有効なglobal transport entity 1件。Service/Route/bridge entityなし |
| API runtime | `kong/api-gateway.yaml` | `[fapi2-demo]` | WP3。foundationの全entityを同一ID・タグで含め、Resource ServerのService/Route/stock pluginを追加 |
| 3rd Party runtime | `kong/third-party-gateway.yaml` | `[fapi2-demo]` | WP5。同様にfoundation全entityを含め、固定UUIDのRoute A/B、OIDC、bridge delegate等を追加 |

foundationの各entityには両方の管理タグを付ける。runtime追加entityには`fapi2-demo`と必要な論理Routeタグを付ける。decKの複数タグはANDである。[公式tag仕様](https://developer.konghq.com/deck/gateway/tags/)に従い管理範囲をfile内へ保存し、diff/sync時に`--select-tag`で別範囲へ上書きしない。runtime fileからCLIタグだけでfoundationを抜き出す運用はしない。

third-partyのglobal transport Entity IDは`88888888-8888-4888-8888-888888888888`とし、runtimeへ同じIDで引き継ぐ。`enabled=true`、service/route/consumer関連付けなし。設定にRoute UUIDがあってもKong plugin EntityをRoute scopeへ変更しない。

foundationはfile内のforeign keyを完結させる。transportの`routes[].route_id`はidentity用のUUID文字列であり、未作成のRoute entityへのforeign keyではない。WP1は上の固定manifestとの一致を検証し、実Routeとの一致はWP5で追加する。third-party foundationにbridge entityがないことは、最終DPの両plugin必須条件を緩めない。

WP1のAPI foundation diffはcreateのみ、既存entityへのupdate/deleteは0。third-partyは新CP内の基盤作成のみ。途中でfoundation entityを変更するときも、runtime fileへの反映と新しいpreviewが必要。既存`kong/kong.yaml`はv1記録として保持し、Enhancementの通常コマンドから選ばない。

WP3のAPI runtime diffではv1のService/Route/bridge等の除去が必要になる。この削除はWP1の基盤受入に含めず、停止時間・旧session・再開手順を示すmigration previewで個別にレビューする。他のタグ範囲やCPのentityを削除しない。既存CPにbridge設定が残る間に、API DPを`KONG_PLUGINS=bundled`だけで起動して成功すると推定しない。

## コマンドとCPの検証順

diff/syncでは`GATEWAY=api|third-party`と`STAGE=foundation|runtime`を必須にする。schema check/syncは`GATEWAY`を必須にし、stageは取らない。`make validate`は利用可能な全stateをcredential不要で検証し、未完成runtime fileをliveコマンドの対象にしない。schemaだけのDP imageや成功を返す仮handlerは作らない。

```sh
make deck-diff GATEWAY=api STAGE=foundation
make deck-diff GATEWAY=third-party STAGE=foundation
make plugin-schema-check GATEWAY=third-party
# 以下は該当WPの完成・previewと適用承認後だけ
make deck-sync GATEWAY=api STAGE=runtime
```

1. mode、GATEWAY、STAGE、fileの存在・完成宣言・タグ、非機密target manifestを検査する。未指定／不正値、ローカルID/name mapping不整合は`.env`読み込み・通信前に非zero。
2. 妥当な入力に限り認証情報を読み、選択したregion/CP IDのmetadataをread-only取得する。実CP名とmanifestの名前が一致しなければ停止する。remote mismatchを「通信前に判定」とは要求しない。decKのname指定は検証済みの名前を使う。
3. third-partyの両schemaを照合する。APIではstateに両custom entityがないことを確認する。既存API CPに登録済みのbridge schemaが残っていても削除しない。
4. 選択fileだけでdiffを取る。失敗、401/403/404、CP未作成、schema driftは停止し、別CPへfallbackしない。syncは同じtarget/stage/fileのreview済みpreviewと利用者の承認範囲を確認してから実行する。

WP1のmockは呼出し先選択と拒否順を検証する。CP metadata、schema、live diffの証明には数えない。前提のCP作成／schema登録が未承認ならnot_runとし、完全受入を保留する。

## self-contained schema契約

`fapi-as-mtls-transport/schema.lua`は外部moduleの`require`なしでCPへ登録できる形にする。global scopeのみ、consumer/service/routeへの関連付け禁止、protocolはhttp/https。本体のPRIORITY 1100とlifecycleはWP5の責務。

必須stringには暗黙defaultを付けない。URLはDP0の固定inventory、fileは下の許可pathのみ。未知field、inline PEM/key、追加Route、任意URL/fallback optionを受け付けない。

| config field | 型／値 |
|---|---|
| `issuer` | string、`https://localhost:8444/realms/fapi-demo` |
| `internal_origin` | string、`https://keycloak:8443` |
| `discovery_url` | string、`https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration` |
| `jwks_url` | string、内部realmの`/protocol/openid-connect/certs` |
| `par_url` | string、同`/protocol/openid-connect/ext/par/request` |
| `token_url` | string、同`/protocol/openid-connect/token` |
| `revocation_url` | string、同`/protocol/openid-connect/revoke` |
| `metadata_certificate_file` / `metadata_key_file` | string、`/etc/kong/fapi/third-party-metadata.crt` / `.key` |
| `routes` | 必須array of record、要素数2。下記5 fieldが各要素で必須 |
| `evidence_correlation_enabled` | boolean、default false。計測fixtureだけtrue |

各Route recordは`route_id`（UUID string）、`logical_route`（A/B enum）、`client_id`、`certificate_file`、`key_file`の**5 field**を持つ。A/Bの値はidentity表と既存`/etc/kong/fapi/route-a.crt/.key`、`route-b.crt/.key`へ完全一致させる。重複UUID、論理Route/client IDの重複・入替、cert pathの入替を拒否する。schemaで検査できる型・許可値と組合せをCP側で検査し、同じ契約を静的validatorとWP5 configureでも確認する。file存在、鍵一致、期限/EKU、bootstrapとの一致はDP configureで判定する。CP側のschema検証を鍵ロード成功として扱わない。

bridgeにはstring enum `assertion_delivery=[header, transport_delegate]`、default `header`を追加する。既存v1設定はfieldなしでheader modeを維持する。third-party runtimeは必ず`transport_delegate`を明示し、Route BのUUID/client ID/certificateとglobal registryを一致させる。WP1ではhandlerを変更しない。delegateの送信時signer、header mode回帰とcontext不備の拒否はWP5で受け入れる。

schema checkはHTTP 200だけでpassにしない。custom schema一覧`GET .../core-entities/plugin-schemas`を全page取得し、期待plugin名が各1件、各`items[].lua_schema`が非空stringであることを確認する。[公式SDKの一覧応答型](https://github.com/Kong/sdk-konnect-go/blob/main/models/components/listpluginschemas.go)には原Luaがある一方、[個別取得の応答型](https://github.com/Kong/sdk-konnect-go/blob/main/models/components/getpluginschemaresponse.go)は`fields`であり、個別GETに原Luaがあると仮定しない。[一覧request型](https://github.com/Kong/sdk-konnect-go/blob/main/models/operations/listpluginschemas.go)の`page[size]`/`page[after]`を使い、進まないcursorやpage取得失敗を成功に変換しない。

一覧の原Luaとレビュー対象fileを、CRLF→LFと最終改行の有無だけ正規化してSHA-256比較する。それ以外の差はdriftとして停止する。paginationの不完了、欠落、重複、原Luaが取得できない場合も停止する。値／取得bodyはログへ出さず、plugin名、CP ID、期待／観測hash、結果だけを記録する。schema syncは別承認であり、差分を自動PUTしてcheckを成功させない。登録済みschemaがDPへ配布／ロードされたかはWP5で別に判定する。schema更新だけでDPへ新payloadが届くとは仮定せず、[公式hybrid要件](https://developer.konghq.com/custom-plugins/konnect-hybrid-mode/)に従い実際の承認済みentity設定反映と全worker受領を確認する。

## 起動前の閉鎖契約

WP1はcomposeの基盤宣言と静的検証を作る。APIは`bundled`、third-partyは`bundled,fapi-as-mtls-transport,fapi-client-auth-bridge`を明示し、image内のdefaultへ依存しない。WP5までは通常入口/UIを起動しない。

DP0のworker bootstrap値はコンテナenvへ置くだけでは不足する。NGINX workerへ引き継ぐ宣言を設け、exact 3.16.0.0のworkerで値が見えることをWP5が証明する。公式の[Konnect-connected DPの設定例](https://developer.konghq.com/plugins/veriknox/)では`KONG_NGINX_MAIN_ENV`を用いているが、別plugin/versionの例であり今回のruntime証跡を代用しない。

UI停止だけをAS通信の遮断とみなさない。起動直後やplugin欠落時のstock metadata/background fetchも対象である。WP5は、CP通信を許可しつつASのpublic/internal originへ到達できないbootstrap段階、全worker ready判定、AS到達と通常入口の開放を順に成立させる。通常DPのhost公開port、共有network、host側8444経由の迂回を含めて閉鎖を検証する。単に`depends_on: healthy`を置く方式では受け入れない。

具体的なcompose/networkと入口開放の実装は、DP0で許容したmake/composeの範囲でWP5が提示する。選んだ仕組みがbootstrap時のAS未送信を実証できなければneeds-designへ戻す。追加AS proxyやTLS検証の無効化で回避しない。この詳細設計は未検証のnetwork isolationを成功済みとは扱わない。

全worker観測は少なくともrun generation、実worker集合、pluginロード、wrapper count=1、bootstrap可視性、registry epoch、非機密config digest、固定Route mapping、ready判定を持つ。古いgeneration／欠けたworker／timeoutは閉鎖。configure変更・worker再起動では閉鎖して再照合する。receiptへ秘密材料・callback・生bodyを保存しない。新しい公開管理APIや本番監視基盤は追加しない。

## 追加受入と分担

| ID | owner | 合格条件 |
|---|---|---|
| WP1-STAGE | WP1 | foundationを2 CPへ選択。API既存v1 fixtureのdelete/update=0、範囲外entity=0。runtime未完成／stage未指定／タグ改変は非zero |
| WP1-TARGET | WP1 | 不正selectorは認証前に拒否。remote CP名不一致はread-only照会後、decK/schema mutation前に拒否。全CP metadata endpointが選択region/IDに一致 |
| WP1-SCHEMA-DRIFT | WP1 | 未登録、違うschema、片方欠落を拒否。APIのlegacy schemaを削除せず、API stateのcustom entity追加を拒否 |
| WP1-IDENTITY | WP1 | Route UUID/client ID/cert pathの正解fixtureと入替・重複negativeを検査。両DPのmountとCP接続先が分離 |
| WP3-MIGRATION | WP3 | runtimeへfoundation同一IDを包含。v1除去と入口停止・復旧をpreview。承認後sync、diff=0、RS試験を実行 |
| WP5-BOOTSTRAP | WP5 | CP設定受領前／transportだけ／両plugin欠落で通常入口閉鎖、AS observer行0。全worker readyの正常系だけ開放。再起動／変更で再閉鎖 |

静的testは選択・所有範囲・identity・secret配置の意味あるnegativeを検証する。TLS/worker/networkは実runtime evidenceで判定する。WP1の受入後もWP3/WP5のruntimeとmigrationは未完成であり、demo成功とは説明しない。
