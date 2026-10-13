# バックエンド分離構成の準備・適用・受入

状態: TP部分適用で停止・固定残差分の復旧準備中／実行受入前（2026-10-13）。資料PR #30はmainへ反映済み、コードは別Draft PR #31。旧WP1～WP6の成功は変更前の5サービス構成の履歴であり、新経路の受入ではありません。[構成と信頼境界](../../ARCHITECTURE.md)、[実装計画](third-party-backend-change-plan.md)、[ADR 0023](../decisions/0023-third-party-backend-separation.md)も参照してください。

## 先に確定する対象

受入runごとに、対象TP Control Plane、既存credentialの利用、コード・設定・image、Compose projectとファイル、port、DB、終了時の停止対象を具体的なプレビューへ記録します。外部CPの読み取りにも、その接続先とcredential利用を許可された環境を使います。raw diff・env・token・秘密鍵・Cookie・assertionを端末や共有資料へ出しません。

Docker環境を分けても、同じTP CPへsyncすれば、そのCPに接続する他DPへも設定が配信されます。旧stackと新しいバックエンド経路を混在させません。API CPやTerraformは今回の変更対象ではありません。

既存デモを使う場合は、CA、A/B証明書、Route B PKJWT/JWK、セッション・ユーザー資格情報、CP/DP identityを維持します。DB snapshotはKeycloak停止を確認してから取得し、コピー一致と原本不変を確認します。新しい空DBの作成や既存DBの初期化を、既存デモ再現として扱いません。今回の候補では原DBをread-onlyでコピーし、隔離snapshotだけを書込み可能にします。

## PKI・role・mount

既存CAで次の2identityだけを追加します。既存の鍵や証明書をローテーションしません。`scripts/generate-pki.py`は完成した既存identityを上書きせず、不完全な組を拒否しますが、ほかの不足identityも生成するため、実行対象と既存ファイルを先に確認します。一般的な`make generate-dev-assets`を既存DBへ無確認で実行しません。

| identity | 用途 |
|---|---|
| third-party-backend | serverAuth、SAN `DNS:third-party-backend`。Backend9444のserver |
| third-party-backend-hop | clientAuth。TP Kongの新Service CertificateとBackendのpeer pin |

TP roleへ`DECK_BACKEND_HOP_CERT_YAML`と`BACKEND_HOP_KEY`を加え、TP runtime envへhop keyを追加します。既存A/B/PKJWT/session値は維持し、API roleにはhop keyを入れません。`scripts/render-runtime-secrets.py`で必要なrole/envを描画できます。生成先はprivate directory0700/file0600とし、値を表示しません。

Backendのread-only mountは次の8ファイルです。PKJWT秘密鍵、CA秘密鍵、hop秘密鍵、refresh token、セッションsecretはBackendへ渡しません。

| 元のPKIファイル | Backend内 |
|---|---|
| ca.crt | /etc/fapi/ca.crt |
| third-party-backend.crt / .key | /etc/fapi/tls.crt / tls.key |
| third-party-backend-hop.crt | /etc/fapi/third-party-backend-hop.crt |
| route-a.crt / .key | /etc/fapi/route-a.crt / route-a.key |
| route-b.crt / .key | /etc/fapi/route-b.crt / route-b.key |

UID/GID1000がhost-owned mode0600鍵を読めること、readiness用0700 tmpfsの所有、Keycloakのsnapshot書込みは実行環境で確認します。失敗時に鍵のpermissionを広げて通過させません。

## TP設定のプレビューと今回専用承認

最小対象は`GATEWAY=third-party STAGE=runtime make deck-diff`です。新しいUI Routeはnative expressionの`http.path ==`をORで組み合わせ、`/`、`/index.html`、`/evidence.js`の3パスだけへ一致させます。`paths`と`regex_priority`は使わず、既存の`router_flavor=expressions`を維持します。[公式の完全一致・ORの説明](https://developer.konghq.com/gateway/routing/expressions/#regular-expressions-usage)を参照してください。

旧案の`~^/`はKongのRoute schemaに適合せず、正規の非作成Routes validationでもHTTP400を再現しました。「decKのfalse-positive」とした判断は撤回しています。固定移行案内の除去adapterと`--silence-events`は撤回し、pureJSON parserを維持します。改変prefix、重複・非有限値、余分な末尾、警告/エラー、不一致の操作集合は拒否します。

初回同期は、レビュー済み4create/6update/0deleteの一致確認後に実行しましたが、CLI nonzeroとなりました。read-only現状確認ではhop CertificateとUI Serviceの作成、A/B Serviceの更新の4操作が反映済み。残りはUI Route/UI transformerの2createと、A/B CORS/OIDCの4updateです。削除・予期しない対象変更はありません。最初のsync失敗rawは保持されておらず、旧Route拒否を単一原因とは断定しません。

新Routeは同じ指定CPの正規Routes validationで受理されました。新しい残差分は専用`migration-recovery` planと新承認票へ結び付け、元4/6票を流用しません。任意のsubsetを許容する対応ではありません。再開前に、人が新Route表現とexact残差分6件を確認します。Docker/IdP操作と新経路の受入は未実施です。

適用には次の新契約を使います。

- private承認票: `.generated/evidence/third-party-backend-runtime-approval-v2.json`、mode0600。
- `schema_version: 2`、`scope: third-party-backend-runtime-v2`、承認済み`plan_type`。
- 当該target/state/role/full diffのSHA-256、完全一致するoperations/summaryへ結び付ける。
- 人が実差分をレビューした後だけ`TP_BACKEND_RUNTIME_V2_APPROVED=YES`でTP runtimeのsyncを許可する。

commit `31e2cd2`でnative Routeと固定残差分guardを実装しました。Manager独立の対象45件・追加確認5件と意味的mutation13件の検出が成功しました。これは宣言・CLI・ローカルの検証であり、DPの実ルーティングやBackend E2Eの受入ではありません。

旧schema1/additive11票は拒否します。wrapperは同期前に正規の非作成Routes online validationを行い、失敗時はsyncを呼びません。続いてfresh diff、source/role/target、承認票の再読を照合します。不一致・予期しないentity/field・警告・削除があれば停止し、guardやscopeを広げません。同期後も同じ対象のdiffと実動作を確認します。

## native実行とIdP

Apple Siliconではbaseと`docker-compose.demo-native.yml`を使います。TP Kongはnative3.16.0.0、Backendは`python:3.13-alpine`にapp.pyをread-only mountします。新Backend GHCR imageは未公開で、このlaneではbuild/publishを必要としません。必要なimage取得も具体プレビューと明示許可の対象です。取得後のimage identityを記録し、そのrunで固定します。

受入候補は別Compose projectと専用networkを使い、全6サービスを作成します。UI/backendにhost portは設けません。loopbackのKeycloak8444とTP18443を使い、ブラウザー入口8443はsupervisorが全TP workerとBackendのreadiness成功後にだけ開きます。旧UI3000/3443は公開しません。`make up`の閉鎖guardは維持し、承認後の具体手順は`--wait`と`--supervise`を使います。最初の4サービスの明示起動には`--no-build --pull never`を使います。supervisorによるBackend/UI起動は`--no-build`だけで、pull無効flagを持ちません。supervisorの開始前に両imageがcacheにあり、レビュー済み参照へ固定されていることを再確認します。

隔離Keycloak起動後、realm `fapi-demo`の対象2clientだけをGETします。現在値は起動前には未照合です。ほかのattrsを保全し、必要時だけ`post.logout.redirect.uris`を次へ変更、readbackで確認します。

- `third-party-fapi-mtls`: `https://localhost:8443/?logout=route-a`
- `third-party-fapi-pkj-mtls`: `https://localhost:8443/?logout=route-b`

`sync-keycloak-demo-data.py`の全体同期はusers/realm/provider等も更新するため、今回の2属性更新に流用しません。終了時はforwardを閉じ、候補projectだけを停止し、元stack・元DBを保持します。CP rollbackやリソース削除は別の具体レビュー対象です。

## 新経路の受入項目

A/B各利用者のlogin/API/refresh/logout、AS提示の元A/B証明書、専用内部hop、Backend→APIのtoken/certificate bindingを実測します。任意/重複Authorizationを実TP入口から送り、拒否またはsession-issued tokenの維持を確認します。Backend迂回や不正path、API側へ直接送るcontrolled spoof/binding負例も区別して確認します。Backend停止・restart/config driftで入口が閉じること、probeがproviderを呼ばないこと、秘密がUI/ログ/エラーへ出ないことを確認します。

source/local TLSやstock fixtureの成功を、新Backend E2Eの成功へ読み替えません。未実施はnot_run、失敗はfailとして保存します。新経路の受入が終わるまでコードPRはDraftを維持し、Pagesの設計段階表示も保持します。
