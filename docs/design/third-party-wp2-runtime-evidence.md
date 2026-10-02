# WP2: 隔離Keycloakの実試験証跡

利用者は[環境preview](third-party-wp2-validation-preview.md)の起動・realm操作・実token試験・cleanupを承認した。Luna / xHighが実装と修正を担当し、Design ownerが隔離fixtureで独立実行した。PR #18のbranch `feat/wp2-keycloak-clients`、baseline main `4ce796d`が対象である。

## 検証範囲

stock Keycloak 26.7.4のpinned imageを専用Compose project `wp2-isolated-keycloak`で起動した。issuerは`https://localhost:18444/realms/fapi-demo`、callbackは`127.0.0.1:8443`。各attemptは新規PKI・認証情報・realmと新規volumeを使い、fixture CAでTLSを検証した。token・code・assertion・Cookie・admin bearerはprocess memory内だけで扱った。

通常環境のissuer 8444、Gateway、Konnect、Terraform resource、通常ブラウザ、OS trust storeはこの検証の対象外である。成功を通常Gateway経路、WP5のAS peer観測、WP6のbrowser E2E、完全FAPI適合へ読み替えない。

## 試験履歴

| Attempt | receipt作成時刻（UTC） | 結果 | 原因・扱い |
|---|---|---|---|
| 01 | 2026-10-02 21:33:23 | 1 fail / 8 not_run | token発行前のJWKSにPS256鍵がなく署名検証で停止。unknown kid時の1回だけのJWKS GETを追加。失敗は保持 |
| 02 | 2026-10-02 21:41:22 | 2 pass / 1 fail / 6 not_run | RS-INT-AUD-02はA/B成功。Keycloakのeffective mapperが補う`userinfo.token.claim=false`をRS-INT-AUD-01の差分guardが検出。全mapperの既定値を宣言へ明記 |
| 03 | 2026-10-02 21:46:22 | 7 pass / 2 fail | B-AUD-01/B-CERT-01はHTTP 400 `invalid_grant`。想定の`invalid_request`と異なるためfail。policy固有の拒否理由を区別できる判定を準備 |
| 04 | 2026-10-02 21:54:55 | **9 pass / 0 fail / 0 not_run** | 固定policy理由の完全一致判定を含めて独立実行。mapper復元・positive control再確認、最終cleanup成功 |

01〜03のfixtureとreceiptを`.generated/wp2-preview-attempt01/`〜`wp2-preview-attempt03/`へ移して保持した。各attemptの専用container・network・volumeはcleanup済み。再試験で既存receiptを上書きしない。

## 判定を維持する修正

Keycloakの[署名鍵選択](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/keys/DefaultKeyManager.java#L54-L78)は、必要なalgorithm/useの鍵がない場合にfallback生成を試みる。harnessはunknown kidの場合だけ検証済み同一originのJWKSを全runで最大1回取得し直す。PS256、RSA、署名用途、一意候補、PyJWTの署名・issuer・時間・audience・nonce検証を維持し、token POSTを再送しない。

[effective mapper](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/mappers/AbstractOIDCProtocolMapper.java#L159-L170)は未設定のUserInfo出力をID token出力から補う。属性mapperはtrue、audience mapperはfalseを明示し、予期しない差分は引き続き更新前に拒否する。

[authorization-code handler](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/grants/AuthorizationCodeGrantType.java#L177-L185)はcode・PKCE検証後のpolicy例外を`invalid_grant`へ変換する。汎用の`invalid_grant`だけではB-AUD-01/B-CERT-01を合格にしない。policy固有の固定理由をmemory内で完全一致照合し、安全なenumだけを記録する判定を再試験する。03のfailは遡ってpassへ変更しない。

## 最終結果

| 受入ID | Route | 層・観測 | 結果 |
|---|---|---|---|
| RS-INT-AUD-02 | A/B | PS256署名・issuer・時間、`azp`、両audience、scope、namespaced claim、route certの`cnf.x5t#S256`を検証。専用mTLS introspectionでHTTP 200、`active=true`と必須claim一致 | 2 pass |
| RS-INT-AUD-01 | A/B | 同一realm/client/user session、署名・時間・binding・API audienceを保ち、introspection audienceだけを除外。HTTP 200、`active=false`。mapper復元後のcontrolは`active=true` | 2 pass |
| A-CERT-01 | A | certなし。AS HTTP 401、`invalid_client` | pass |
| A-CERT-02 | A | Route B cert。AS HTTP 401、`invalid_client` | pass |
| B-AUD-01 | B | assertion audienceだけtoken URLへ変更。AS HTTP 400、`invalid_grant`、`oauth_reason=client_assertion_audience` | pass |
| B-CERT-01 | B | 有効PKJWTとgrantを維持しcertだけ除外。AS HTTP 400、`invalid_grant`、`oauth_reason=mtls_client_certificate_missing` | pass |
| B-JTI-01 | B | 別fresh code/verifierの1回目がtoken発行成功。同一の有効assertionを2回目の未使用codeへ送信し、AS HTTP 400、`invalid_client` | pass |

User profile同期、demo user routing属性同期も成功した。B-AUD-01/B-CERT-01のsafe enumは、[assertion executor](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/executor/SecureClientAuthenticationAssertionExecutor.java)と[HoK executor](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/executor/HolderOfKeyEnforcerExecutor.java)の固定拒否理由に完全一致した場合だけ付く。未知の理由、generic `invalid_grant`、別enum、HTTP 401、TLS/local失敗は合格にしない。

最終receiptは`.generated/wp2-preview/evidence/wp2-receipt.json`（Git外、0600）。04の専用container・network・volumeも削除した。fixture材料・全attemptのreceiptは保持し、生token・code・assertion・Cookie・秘密鍵・生response bodyを証跡へ書かない。

修正後の独立`make validate`、`make test`は成功。WP1 19件、WP2 26件、実PS256正常・改変・別alg、unknown-kid refresh上限、effective mapper収束、policy理由の誤判定・非露出を確認し、crypto skipなし。pluginの変更はなく、PR準備時の`make test-plugin`成功を継続する。最終headのCIはPR status checksに記録する。

## 残作業

利用者merge後のmain上の独立positive/negative確認、Technical Completion Report、利用者の受入・Issue #8 closeは別途必要である。通常Keycloakへの適用は今回の隔離preview承認に含めない。WP3はWP2受入前に開始しない。
