# 隔離した WP2 Keycloak 検証

この harness は Keycloak 26.7.4 だけを固定 loopback port `127.0.0.1:18444` で起動し、Route A、Route B、専用 introspection client の認証と token introspection を検証します。利用者が隔離runtimeとcleanupを承認し、修正後のfresh fixtureで9結果すべて成功しました。専用container・network・volumeはcleanup済みです。[実試験証跡](../../docs/design/third-party-wp2-runtime-evidence.md)に途中の失敗も保持しています。既存の通常 Compose project、realm、PKI、`.env`、`.generated/` の内容は再利用しません。

## 実行環境

必要なものは Docker Compose、OpenSSL、Python 3、`requirements-dev.txt` の依存です。runner は PyJWT で PS256 署名、issuer、時間、audience、nonce を検証します。通常ブラウザを起動せず、認可ページの login と consent form を process 内で処理します。Keycloak Cookie は process-local `CookieJar` のみに保存します。

TLS は新規 fixture CA を使い、Keycloak `https://localhost:18444` と callback `https://localhost:8443` の証明書を検証します。callback listener は `127.0.0.1:8443` に固定され、port が使用中なら検証は停止します。OS trust store、browser profile、通常ブラウザの Cookie は変更・参照しません。authorization code、token、assertion、password、Cookie、response body は process memory の外へ出しません。

## Fixture の生成

`prepare_wp2_preview.py` は新しい `.generated/wp2-preview/` だけを作ります。既存 path または `.generated` symlink がある場合は停止します。ここでは container を起動しません。

```sh
python3 tests/harness/prepare_wp2_preview.py --allow-create-isolated-preview-assets
```

コマンドは CA、3 つの mTLS client certificate、Route B の PS256 key、realm import、ランダムな bootstrap admin と sales user の credentials を生成します。`bootstrap.env`、`accounts.env`、秘密鍵、render 済み realm は mode `0600`、fixture directory は mode `0700` です。credentials を表示するコマンドはありません。realm import の2人の demo user は email を username と同じ値にします。

## Keycloak の起動

別途承認を得た後にのみ、次を実行します。wrapper は起動前に固定 Compose project の container が存在しないこと、固定 volume `wp2-isolated-keycloak-data` が存在しないことを確認します。Docker daemon、container lookup、volume lookup の確認に失敗した場合も起動しません。起動は pinned Keycloak image のみを `--no-build` で行います。

```sh
python3 tests/harness/start_wp2_preview.py --allow-start-isolated-keycloak
```

Compose file は `--project-directory .` で repo root を基準に asset mount を解決します。fixture asset と credential bind mount は mode `0600` です。pinned Keycloak image の default UID 1000 では host file の owner/group によって読めない可能性があるため、この隔離 service だけ `user: "0:0"` で実行します。volume 内の realm database もこの user が所有します。service は `privileged` ではなく、host mount は全て read-only です。normal Compose の user 設定は変えません。Keycloak は localhost 以外に bind しません。root `docker-compose.yml` の gateway、UI、readiness gate はこの project の対象外です。

## Probe の実行

realm user-profile の同期、login session、PAR、consent、authorization code、token 発行、mapper の一時変更は Keycloak state を変更します。これらの操作について別途隔離環境の承認を得てから、以下を1回実行します。RS-INT-AUD-02 は常に実行します。2つの optional flag は RS-INT-AUD-01 と A/B の AS negative ケースを追加します。

```sh
python3 tests/harness/wp2_flow.py \
  --allow-isolated-auth-and-realm-changes \
  --run-audience-negative \
  --run-as-negatives
```

runner は discovery endpoint が `https://localhost:18444/realms/fapi-demo` と一致することを確認し、全ての advertised endpoint を同じ origin に制限します。authorization は PAR、PKCE S256、client 別の登録済み redirect path と `state` 検査を経由します。Route A と Route B は隔離 fixture 用に新しく生成した certificate を使い、それぞれ既存の Route A/B subject `CN=kong-fapi-mtls` / `CN=kong-fapi-pkj-mtls` を維持します。新しい client ID を導入しても、通常環境の Route certificate/key は再生成しません。Route B assertion の `kid` は `scripts/export-rsa-jwk.py` と同じ SPKI DER SHA-256 thumbprint から作ります。introspection は専用 `api-gateway-introspection` mTLS certificate を使います。

Keycloak が初回の PS256 token 発行時に署名鍵を作ると、発行前に取得した JWKS にその鍵がない場合があります。runner はtokenの`kid`がJWKSにない時だけ、discoveryで検証した同一originの`jwks_uri`をTLS検証とredirect拒否を維持して1回だけ再取得します。再取得後も`kid`、`kty=RSA`、`use=sig`、`alg=PS256`が一致する鍵が1つだけ必要で、PyJWTで署名とclaimsを検証します。同じkidに別alg/useの鍵がある場合はPS256鍵だけを選び、同じ条件に合う鍵が複数ある場合は拒否します。署名鍵確認のためにtoken requestは再送しません。

Keycloak realm import で demo user の未定義 custom attribute が欠落しても probe を始めないよう、runner は先に repository の `user-profile.json` を反映し、fixture の2人を username exact lookup します。両方の lookup と属性形状を事前確認後、`department`、`departement`、`route` だけを unknown attributes と併合した partial PUT で同期し、post-read 収束を確認します。duplicate lookup、profile sync、user attribute sync のどれかが失敗すると token flow は開始しません。

RS-INT-AUD-01 は各 route の正の control token を作り、active introspection を確認した後、同じ realm・client・CookieJar user session のまま introspection audience mapper 1項目だけを無効にします。新しい PAR/code/verifier の token が API audience、signature、time、session、certificate binding、scope、namespaced claim を保ち、`active=false` になることを検証します。mapper は `finally` で元へ戻し、control token の `active=true` も再確認します。

AS negative の拒否はlayer、sanitized OAuth error code、必要な時は固定enumの理由に分けて記録します。A-CERT-01/02はtoken requestのcertificateだけを変えます。B-AUD-01は有効なB assertionのaudienceだけを変えます。B-CERT-01は有効なPS256 assertionと新しいgrantを使い、Route B certificateだけを外します。通常のauthorization-code grant処理はcode、session、redirect URI、PKCEを検証した後にtoken-request client policyを実行します。Keycloak 26.7.4はそこで発生したclient-policy exceptionを外側の`invalid_grant`へ変換するため、B-AUD-01はHTTP 400と`client_assertion_audience`、B-CERT-01はHTTP 400と`mtls_client_certificate_missing`の組が一致した場合だけAS拒否としてpassにします。runnerはこの2つの既知source detailをmemory内で完全一致比較してenumへ変換し、raw description、response body、assertion、tokenを表示・receipt保存しません。`invalid_grant`だけ、HTTP 401、未知detail、他のreason、TLS handshake errorはfailです。

RS-INT-AUD-02 A/Bの成功token交換をpositive controlとして先に実行します。各negativeにも新しいPAR、code、PKCE verifierを使い、既知のclient-policy拒否がcode/session/redirect/PKCEの先行失敗を誤認していないことをsourceの処理順と照合します。B-JTI-01は別々のfresh code/verifierと、有効期間内の同一assertionを使います。2回目は`invalid_client`だけを合格とし、`invalid_grant`やTLS/local失敗はreplay成功と数えません。

## 証跡と cleanup

runner は `.generated/wp2-preview/evidence/wp2-receipt.json` に sanitized receipt を mode `0600` で一度だけ作成します。ケースごとに acceptance ID、client ID、`pass`/`fail`/`not_run`、拒否 layer、HTTP status、既知 OAuth error enum、安全な固定文言の観測結果を記録します。unknown error code、error description、body、token、code、assertion、Cookie、secret は記録しません。既存 receipt は上書きしません。

専用 project の停止と volume 削除にも別途承認を得た後、次を実行します。固定 project `wp2-isolated-keycloak` に限って container、orphan、named volume を削除します。`.generated/wp2-preview/` の fixture と receipt は残ります。

```sh
docker compose --project-directory . \
  --project-name wp2-isolated-keycloak \
  -f tests/harness/docker-compose.wp2.yml \
  down --volumes --remove-orphans
```

通常 demo gateway の起動、`make up`、realm sync、Konnect/Terraform 操作はこの手順に含みません。

## 隔離した WP3 API Resource Server 検証

WP3 は `kong/api-gateway.yaml` のAPI runtime stateを、専用Compose project `wp3-isolated-api-rs`で検証する。通常の`make up`、通常Composeのreadiness、UI、third-party Gateway、Konnect、Terraformには触れない。起動するserviceは、stock Kong Gateway `3.16.0.0`、Keycloak `26.7.4`、内部専用のstdlib TLS captureだけで、3 imageはそれぞれCompose fileに固定digestを記載する。captureは検証用TLS upstreamで、placeholder production handlerではない。

ホスト公開はloopbackだけで、APIは`127.0.0.1:18443`からKong container `8443`、Keycloakは`127.0.0.1:18444`からcontainer `8443`へ接続する。OAuth callback listenerはflow実行中だけ`127.0.0.1:8443`で開く。captureはCompose network内の`pop-verifier:9443`のみで、host portを持たない。GatewayのAPI RouteはSNI `localhost`と`kong-api`を受け、API ServiceからcaptureへのTLSはfresh fixture CAと専用upstream client certificateで検証する。Keycloakは実際のdiscovery/JWT issuerを`https://localhost:8444/realms/fapi-demo`のまま広告し、fixtureだけのTLS接続先は18444へloopback mapする。Kongからのdiscovery/backchannelはCompose内の`https://keycloak:8443`を使う。

隔離fixtureではAdmin APIをcontainer loopback `127.0.0.1:8001`だけでlistenし、Admin GUIは`KONG_ADMIN_GUI_LISTEN=off`とする。GUIを既定で有効にしたpublic-generated configには追加のNGINX includeが現れ、pinned四ファイルinclude graphのstrict TLS parserがfail closedしたためである。通常ComposeのAdmin APIとGUI設定は変更しない。

fixture生成器のコードだけWP2から再利用し、CA、全certificate/private key、Route B signing key、demo accountとrealm stateは`.generated/wp3-preview/`へ新規生成する。既存WP2 fixture、通常`.env`、通常PKI/realmは読まず、licenseは起動時process environmentの存在だけを確認する。mode `0700` directoryと`0600` filesを使い、secret mountsはread-onlyにする。隔離serviceを`user: "0:0"`で実行するのは、host側のowner-only fixtureをcontainerの別UIDに公開せず読み取るためであり、通常Composeのuser設定は変えない。Composeのquiet config検査はAPI keyを子process environmentから受け取り、解決済み設定を出力しない。

次のコマンドは新しいprivate fixture filesを生成し、pinned imageとquiet Compose configをread-only確認する。containerは起動しない。

```sh
python3 tests/harness/prepare_wp3_preview.py --allow-create-isolated-preview-assets
```

起動は具体的なpreviewを確認した後の別操作で、starterは準備receipt、state/compose/helper/fixture hashes、fixed project、image digest、ports、process-local license presenceを再確認してから、上記3 serviceだけを開始する。

```sh
python3 tests/harness/start_wp3_preview.py --allow-start-isolated-wp3-runtime
```

flow、Keycloak-issued access tokenによる実Gateway試験、runtime receiptが完成した後、同じ固定projectだけを停止し、fresh private PKI/accounts/realm/key filesを削除するcleanupは別操作にする。sanitized preparation/runtime receiptsはexclusive-createで`.generated/evidence/`に残る。

```sh
python3 tests/harness/cleanup_wp3_preview.py --allow-cleanup-isolated-wp3-runtime
```

最新の隔離runtime receipt `wp3-runtime-receipt-1791014398144929000.json`はstrict validatorを通過し、29 rows中28 pass / 1 fail / 0 needs-designを記録した。full WP3受入はLEAK-01のためfailである。TLSはpinned `nginx -T`からAPI HTTP listenerのTLS 1.3 policyを確認し、TLS 1.2 strong/weak rejection controlsがpassした。1001件目はHTTP 400とparser/API marker delta 1/1、999件controlを確認した。LEAK-01は190/190候補を調べ、cookie 2 / OAuth token 3 / unknown 5の10 matchesとcredential patternsを検出してfailを維持する。Keycloakのsession-state cookieは1件、unknownは5件、Kong APIはcookie 1とOAuth token 3、verifierは0。API responses 21件/21,917 bytesはclean。raw logs/valuesは保持しない。category/source/field/context countsは診断情報であり、漏えい原因の確定ではない。専用project、volume、fixture、portsのcleanupをrootが確認した。過去receiptは変更しない。receipt後にOIDC前のquery-token-name guardをroute-scoped inline Luaとして追加し、pure Lua/static checksを通した。exact runtimeでのreject/positive controlは未検証で、最新receiptの受入結果には含めない。この補完はstock OIDCの挙動と区別する。
