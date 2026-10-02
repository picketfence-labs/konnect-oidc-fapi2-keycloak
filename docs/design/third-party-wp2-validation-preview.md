# WP2: 隔離Keycloak検証の環境変更preview

Issue #8のコード・fixture・PR準備は利用者承認済み。新規fixture秘密材料のローカル生成と設定previewはこの準備に含む。以下の実TLS/token検証は候補であり、Docker起動・realm適用・token発行は未実施。実装のfreezeと独立レビュー後、利用者がこの範囲を承認してから実行する。

## 対象と変更範囲

| 項目 | 候補 |
|---|---|
| 作業checkout | `/private/tmp/konnect-oidc-fapi2-wp2`、branch `feat/wp2-keycloak-clients`、baseline main `4ce796d` |
| Compose file | `tests/harness/docker-compose.wp2.yml` |
| Compose project | `wp2-isolated-keycloak` |
| 起動service | `keycloak`だけ。stock Keycloak 26.7.4、repositoryと同じdigestを使用 |
| container user | 隔離fixtureだけ`0:0`。hostの0600 fileを読み込むために指定し、秘密fileの権限を広げない。privilegedなし、host mountはread-only、書込先は専用volume |
| listener | host `127.0.0.1:18444` → container `8443`。client certificateは`request`、fixture CAをtruststoreへ登録 |
| 認可callback | fixture runnerのHTTPS listener `127.0.0.1:8443`。新規fixture certificateを使用し、runner終了時に閉じる。使用中なら停止し、既存processを置き換えない |
| 永続領域 | 専用volume `wp2-isolated-keycloak-data`。既存同名project/volumeを確認し、無断流用しない |
| 入力材料 | 当該checkoutの`.generated/wp2-preview/`に新規生成するfixture PKI・認証情報・realm。read-only mount |
| realm/client | 隔離realm `fapi-demo`、新Route A/B clientとintrospection専用client、demo user・user profile・claim mapper・FAPI policy |
| 認可driver | process内だけのCookieJarでKeycloak login/consent formを扱う。fixture user credentialsは秘密fileからmemoryへ読み込む |
| 実行中の変更 | user profile設定とdemo userのrouting属性同期、test userの認可・同意・session作成、PAR・code/token発行、introspection audience mapperの切替と復元 |
| 証跡 | token/code/assertion/cookieはmemory内。Git外のsanitized receiptだけを保存 |

通常環境のissuer `https://localhost:8444/realms/fapi-demo`に対して、隔離fixtureは`https://localhost:18444/realms/fapi-demo`を使用する。fixtureの検証ではこの差を記録し、同一issuer・realm・client・sessionのpositive/negativeを比較する。隔離試験の成功を通常Gateway経路の成功へ読み替えない。

既存workspaceの`.env`、PKI、Keycloak data、Terraform stateはfixtureへコピーしない。Gateway・Upstream・UI・Konnect resourceはこの検証の対象外であり、通常`make up`のWP5 readiness条件は維持する。

認可driverは通常ブラウザのCookie・profileを使用せず、OSのCA trust設定を変更しない。これはKeycloakの実認可フローを使うWP2事前確認であり、WP6のbrowser E2E証跡を代替しない。

## 最初の判定

| 受入ID | 実試験と判定条件 |
|---|---|
| RS-INT-AUD-02 | A/Bの実certificate-bound tokenを専用clientのmTLSでintrospectionし、`active=true`、`cnf`一致、両audience、scope、namespaced claimを確認 |
| RS-INT-AUD-01 | 同一realm/client/sessionのpositive referenceと比較。署名・期限・API audience・bindingを維持し、introspection audienceだけ欠くtokenで`active=false` |
| A-CERT-01/02 | 有効なtoken grantを用い、Route Aのcertificateなし／Route B certificateでASのclient認証拒否を確認 |
| B-AUD-01 | 有効なgrant・署名・鍵・時間を維持し、assertion audだけtoken endpoint URLへ変更してAS拒否を確認 |
| B-JTI-01 | 同一assertionを有効期限内に再送。2回目には別のfresh codeと対応するPKCE verifierを用い、code再利用・期限切れとの混同を防ぐ |
| B-CERT-01 | 有効なgrantとPKJWTをcertificateなしで直接ASへ送り、token発行拒否を確認 |

送信guardの`not_sent`はdirect AS拒否と別結果にする。RS-INT-AUD-02の必須項目が欠ければ`needs-design`としてIssueへ報告し、WP3へ進まない。

## 準備済みの入力と実行コマンド

入力材料は次のコマンドで新規生成した。既存出力directoryのreuseは拒否するため、再実行しない。directoryは0700、秘密fileは0600、symlinkなしを確認済み。通常環境の鍵を再生成せず、隔離fixtureでは同じRoute certificate subjectの別鍵・証明書を生成した。

```sh
python3 tests/harness/prepare_wp2_preview.py --allow-create-isolated-preview-assets
docker compose --project-directory . --project-name wp2-isolated-keycloak \
  -f tests/harness/docker-compose.wp2.yml config --quiet
```

候補の起動・probe・停止は、上記checkoutをcwdとして専用projectへ限定する。起動wrapperはDocker daemonの確認、同名project containerと専用volumeの不存在確認に失敗した場合も停止する。pinned imageを`--no-build`で起動する。imageはcacheに存在することを読み取り確認済み。別環境でcacheにない場合はQuayから取得する。

```sh
python3 tests/harness/start_wp2_preview.py --allow-start-isolated-keycloak

python3 tests/harness/wp2_flow.py \
  --allow-isolated-auth-and-realm-changes \
  --run-audience-negative \
  --run-as-negatives

docker compose --project-directory . --project-name wp2-isolated-keycloak \
  -f tests/harness/docker-compose.wp2.yml down --volumes --remove-orphans
```

Composeの`env_file`は当該checkoutの`.generated/wp2-preview/bootstrap.env`に固定する。runnerは`requirements-dev.txt`を導入したPython環境で実行する。専用Composeの`config --quiet`は成功済み。起動・realm変更・token発行は未実施。

実行後はmapperを復元し、専用projectを停止して専用volumeを削除する。fixture用Compose networkも削除する。取得したimageと`.generated/wp2-preview/`の秘密材料・sanitized receiptは残る。receiptはfixtureへ隔離するため`.generated/wp2-preview/evidence/wp2-receipt.json`（Git外、0600）へ保存し、既存fileは上書きしない。停止・cleanupの失敗は正常終了へ変換せず報告する。追加実行が必要なら、既存receiptを保持し、fresh fixtureの作り直しと再試験範囲を先に整理する。

実行手順と結果の秘匿範囲は[fixture README](../../tests/harness/README.md)を参照。実試験は全9結果（RS-INT-AUD-02/01を各A/B、AS negative 5件）が対象である。`not_run`やTLS失敗をAS拒否成功へ読み替えない。
