# バックエンド分離構成の準備・適用・受入

状態: ソース・ローカル検証済み／実行受入前（2026-10-13）。資料PR #30はmainへ反映済み、コードは別Draft PR #31。旧WP1～WP6の成功は変更前の5サービス構成の履歴であり、新経路の受入ではありません。[構成と信頼境界](../../ARCHITECTURE.md)、[実装計画](third-party-backend-change-plan.md)、[ADR 0023](../decisions/0023-third-party-backend-separation.md)も参照してください。

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

最小対象は`GATEWAY=third-party STAGE=runtime make deck-diff`です。decK1.53.1では人向けイベントがJSONの前に付くため、wrapperは正規`--silence-events`を指定します。純JSON・完全な件数・警告/エラーなしの検査を維持します。

今回の移行を実diffのJSONで診断した結果は4create/6update/0deleteです。作成はhop Certificateとstatic UI Service/Route/transformer、更新はA/B Service、CORS、OIDCの戻り先です。修正後wrapperでの外部再取得は自動承認レビューが明示許可不足として拒否したため、まだ受入済みではありません。ソース上のbootstrap15createやnoop0の許容は、今回の移行承認を別planへ流用する許可ではありません。

適用には次の新契約を使います。

- private承認票: `.generated/evidence/third-party-backend-runtime-approval-v2.json`、mode0600。
- `schema_version: 2`、`scope: third-party-backend-runtime-v2`、承認済み`plan_type`。
- 当該target/state/role/full diffのSHA-256、完全一致するoperations/summaryへ結び付ける。
- 人が実差分をレビューした後だけ`TP_BACKEND_RUNTIME_V2_APPROVED=YES`でTP runtimeのsyncを許可する。

旧schema1/additive11票は拒否します。wrapperは同期直前のfresh diff、source/role/target、承認票の再読を照合します。不一致・予期しないentity/field・警告・削除があれば停止し、guardやscopeを広げません。同期後も同じ対象のdiffと実動作を確認します。

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
