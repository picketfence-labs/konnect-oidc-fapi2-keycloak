# 完了した検証の履歴

実行前プレビュー5件を整理し、完了した検証の結果と制約を集約した記録です。最新の判定は[WP5受入表](third-party-wp5-acceptance.md)と[WP6受入表](third-party-wp6-acceptance.md)を参照してください。古い一回限りの起動手順は再利用しません。harnessと試験専用ソースは回帰検証のため維持します。

## 検証層と結果

| 検証 | 結果 | 証明できる範囲・限界 |
|---|---|---|
| WP2: Keycloak単体 | 9ケース受入済み | A/B認証、束縛、introspection等。[実行結果](third-party-wp2-runtime-evidence.md)を参照 |
| WP3: 隔離API Gateway | 37/37 | API側introspection、PoP、audience/scope、TLS、header/query負例。通常統合は後続で別確認 |
| WP5: direct TLS observer v3 | 40/40 | AS単体TLS観測。34操作、OFF 0行、ON 21行、証明書対応付け18件。8組のOFF/ON HTTP状態一致、TLS負例4種類と前後の正常対照、後片付けを確認。KongのOAuth成功の証拠ではない |
| WP5: 再入r4 | 3モード通過 | OFF→ON、ON→ON、ON→OFFでcanonical行数[1,1,0]、再入count[[],[2,3,4],[]]。全PAR401。重複抑制を示し、OAuth成功は示さない |
| WP5: stock v15 | 受入済み | 標準PKJWTのPAR201、token200、callback302、セッション/logout、access/refresh両revoke200。3操作のAS側Route B証明書を対応付け。relayを介するため直結transportの証拠ではない |
| WP5: AS直結v2 | 受入済み | 44.564秒。A/BのPAR201、コード/refresh200、callback302、保護GET200、logout。13操作を証明書へ対応付け、4応答のcnf一致。BのPS256・issuer文字列aud・iss/sub・TTL60秒以内・異なるjtiを確認 |
| WP5: 拡張flow v6 | 受入済み | 43.869秒。issuer不一致401と正当callback302、A/Bの2回のrefresh rotation、PARパラメーター、15操作のpeer対応付け。challenge新規性の開始要求間比較は未記録 |
| WP5: guard v3 | 承認範囲で受入済み | 45.681秒。header/query/bodyのassertion持込み400、旧世代の入口503とAS到達0、reload時のPID/世代変更。全workerへの全HTTP case強制配信は未網羅 |
| WP5: native起動preflight | 5ケース通過 | pluginありの起動対照と、欠落時のnetworkなし停止。通常OAuthフローの再実行ではない |
| 通常統合・WP6 | 受入済み | 承認済みmainで2 CPへ統合。UI allowlist、切替、clean checkoutの5サービス再現。HTTPS結果画面の実browser検証はCA信頼エラーで未実行 |

## 失敗試行と補正

| 試行 | 観測と対応 |
|---|---|
| observer full-reactor v1～v3 | v1はdpkg一覧のsort不整合でJava compile前に停止。v2/v3はcompile exit1。v3の根因は未確定。full-reactor v4案は撤回し、成功扱いにしない |
| direct TLS v1 | 30/32。期限切れ証明書のTLSエラー分類が不足 |
| direct TLS v2 | 39/40。ON scanは22行すべてobserver_failure、対応付け0。行未出力ではない。固定Quarkusの`UriInfoImpl.getPath(false)`例外をオフラインで再現したが、runtime receiptは例外クラスを保持していない |
| observer補正 | `RoutingContext.request().path()`で固定5パスだけを照合。query/body/token/cookieを読まず、13項目に制限。OFF guardをAPI呼出し前に置き、重複記録を抑制 |
| 再入r3 | 187秒の起動timeout、PAR前に停止。観測0、漏えい0、回収済み。internal networkからhost loopbackへ到達できず専用bridgeへ補正 |
| stock v1～v6 | entrypoint誤り、inspect timeout、network到達、form guard、client_id guard等で停止。未実行・置換済みの版を成功扱いにしない。v4/v5は署名未検査・AS未転送 |
| stock v7～v14 | v7でPAR client_id項目欠落を実測。v8で公開JWKのkid登録を補正しPAR201。v9/v11もPAR201。v14はcallback fragment判定で拒否。v15で標準login_tokens設定とsession/logoutを確認 |
| 直結v1、flow v4/v5 | v1はNginx環境変数で起動失敗。v4/v5はharness guardの不整合で失敗。修正後v6の成功と区別し、失敗receiptを保持 |

公開runtime JARを用いた試験imageの作成方法は[ADR 0017](../decisions/0017-wp5-published-runtime-jar-fixture-build.md)、再入計測は[ADR 0018](../decisions/0018-wp5-request-local-reentry-probe.md)、標準実装の本文を変更しない境界は[ADR 0019](../decisions/0019-wp5-stock-claim-fixture-boundaries.md)を参照してください。

## 一次receiptの識別情報

以下の一次receiptはGit外の`/private/tmp/`に保存したものです。保存先の存在は環境に依存します。表は履歴の照合用で、再実行・上書き用のパスではありません。raw token、JWT、jti、body、cookie、password、鍵、完全な証明書、raw logは公開資料へ載せません。

| 検証 | receiptファイル名 | SHA-256 |
|---|---|---|
| direct observer v3 | `wp5-as-mtls-observer-run-receipt-20261004-v3.json` | `93f3503abff52ee38449130bc131484664d0c96f8ad35e45b8a6f4924b97709c` |
| 再入r4 | `wp5-as-reentry-probe-run-receipt-20261004-v4-r4.json` | `0649988015f31ea238683540c8eab0be1991f8001a79a90ba3f73d6dc7e1b515` |
| stock v15 | `wp5-as-peer-stock-par-run-receipt-20261004-v15.json` | `f0348037bf6796be694f9a00d58bcfeea0b963b8547f16bc5383a4c8b4257519` |
| AS直結v2 | 直結系v2の一次receipt（Git外） | `5283c0740b1dbe02ab64df02af3b997c326d51d348860ecf55131025f4931cb9` |
| 拡張flow v6 | 直結系v6の一次receipt（Git外） | `9b628ed21e550432405697ee7ac4281fb3b98936c0a087120774ec9ec3424ebd` |
| guard v3 | 直結系v3の一次receipt（Git外） | `86cafd4edd712b4df047522355763e3f8c9e47d2748be9b4462ce865e9326a97` |

独立reviewは`.generated/evidence/`の`wp5-root-direct-terminal-review-1791085120188078000.json`、`wp5-root-reentry-r4-terminal-review-1791092645025522000.json`、`wp5-root-stock-v15-terminal-review-1791101147900716000.json`、`wp5-root-transport-v2-terminal-review-1791106088625503000.json`、`wp5-root-transport-v6-terminal-review-1791108590659333000.json`、`wp5-root-transport-v3-terminal-review-1791106594216671000.json`、`wp5-root-native-startup-guards-1791106787009061000.json`に記録しています。

## 通常構成への移行

初期プレビューのcreate/delete件数やstate hashは適用前候補の履歴です。現在の操作手順へ流用しません。通常統合は[ADR 0020](../decisions/0020-normal-demo-runtime-sync.md)と最終受入表に記録しています。API側の`cache_tokens_salt`既知差分は追加syncせず、read-only diffで識別します。revocation metadataの差分は[ADR 0021](../decisions/0021-wp5-revocation-metadata-gap.md)の範囲で開示します。
