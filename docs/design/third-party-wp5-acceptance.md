# WP5実装・受入対応表

## 判定（2026-10-04）

顧客向けデモのAS側の必須機能と、issuer不一致拒否・refresh rotation・PAR parameterは隔離環境で動作した。通常環境への適用、main統合と利用者受入は未完了。Issue #11を自動closeしない。

目的は、顧客要件をなるべくKong標準機能で実装して実演すること。本番FAPI 2.0完全準拠、認定、iss欠落guard、開始CSRF追加防御、DPoP、厳格な個別失効SLAは今回の完成条件に追加しない。stock PAR/revoke本文を維持し、PARのclient_id欠落はRFC 9126の既知gapとして開示する。

## 受入条件と証跡

`pass`は指定した検証層での成功。`partial`には未実行の部分が残る。unit/nativeの成功を実AS、通常hybrid DP、通常supervisor、main受入の成功へ読み替えない。

| 受入ID | 実装箇所 | fixture・層 | 結果・限界 |
|---|---|---|---|
| AS-MTLS-OBS-01 | test-only observer、stock fixture | direct TLS v3、再入r4、stock v15 / 固定image＋実AS | pass。TLS40/40、stock署名/PAR/session/logout、実peer join。計測imageは通常構成に入れない |
| A-PAR-01、B-PAR-01、B-PKJ-01 | third-party state、transport、bridge | 直結v2 / 固定Kong＋Keycloak | pass。A/B各PAR201→code200→callback302→session。AはTLS認証、BはPKJWT＋mTLS |
| A-CNF-01、B-CNF-01 | Route別AS identity | 直結v2 / 実AS token応答 | pass。code/refresh4応答のcnfが送信leafと一致。API側PoPはWP3証跡、通常E2Eは未実行 |
| B-TRANSPORT-01 | transport全endpoint、bridge送信時signer | 直結v2 / 実AS observer | pass。BのPAR/code/refresh/access revoke/refresh revoke各1件。PKIX・期限・EKU・leaf照合、PS256/issuer文字列aud/TTL/jti判定 |
| AS-META-MTLS-01 | 専用metadata identity | 直結v2 / 実AS observer | partial。fresh cacheのdiscovery2/JWKS1は専用peerで成功。background/threadの全形態・全worker HTTP担当の網羅は未実証 |
| META-01、META-02 | 固定issuer/endpoint、bridge discovery | unit、直結v2 | partial。bridge issuer確認と固定origin/endpointへの実接続は成功。discovery全endpointとの対応表を通常環境でも確認する |
| RT-01 | stock session/refresh | 直結v2 / 実user＋実AS | pass。両Routeで期限後の同一証明書refreshと保護GET200 |
| RT-ROT-01 | realm rotation、stock session | 拡張flow v6 / 実AS＋stock session | pass。A/Bとも2回の期限後refreshが成功。最初の応答でtokenが変わり、2回目はその更新値を使ったことをworker共有辞書内の比較で確認。token/hash値は非公開 |
| PAR-01 | stock PAR設定 | 直結v2 / 実AS | pass（デモ動作）。PARより先の認可開始なし。RFC 9126適合はgapを維持 |
| PAR-02、PKCE-01 | stock PAR/redirect/PKCE | 拡張flow v6 / 最終wire＋browser | PAR-02 pass。両Routeのqueryはclient_id/request_uriだけ、nonceは64文字以下、callback URIは固定。PKCEはS256/challenge存在を確認。異なる開始要求のchallenge比較は未記録でpartial |
| B-AUD-02、B-SPOOF-01 | bridge、transport | unit/native、guard v3 / 実Kong worker | pass（範囲限定）。issuer文字列audの署名、header/query/body assertion偽装400。AS側wrong-audはWP2の証跡 |
| ISS-01 | stock callback処理 | 拡張flow v6 / 実Kong callback | pass。A/Bとも改変issを401拒否、同じ正規code/state/cookieの対照は302/session成立。code交換は各1回。iss欠落guardは作らない |
| AS-TRANSPORT-GUARD-01 | transportのform/identity/ledger/endpoint guard | unit/native＋直結v2 | partial。未知origin/HTTP/redirect/重複POST/変更hint同一tokenの拒否、異なる2 revokeの許可。実ASで2 revoke成功。fresh assertion再送・並行A/Bの全負例は通常受入へ残る |
| AS-TRANSPORT-LIFECYCLE-01、WP5-BOOTSTRAP | Docker preflight、worker snapshot、local marker、supervisor | guard v3＋native起動preflight＋unit | partial。2 worker初期化、marker欠落/config不一致/reload/古いepochで503/AS0、plugin欠落起動前停止。HTTP各caseを全workerに強制配信した証拠、通常hybrid/supervisorの入口/UI閉鎖は未実行 |
| HDR-01、TLS-01 | third-party Service/OIDC、API側WP3 | state validation＋実AS＋WP3 isolated | partial。Authorization header/TLS verify設定、AS実TLS、WP3のRS保護は確認。通常3rd Party→API→Upstreamの統合確認は未実行 |
| REDIR-01 | 固定login/logout URI | state validation＋直結v2正常flow | partial。固定terminalへの遷移を確認。外部URL誘導負例は通常統合で確認する |
| logout/reset、LEAK-01 | stock logout設定、bounded diagnostics、cleanup | 直結v2、guard v3 | pass（隔離範囲）。access/refresh revoke200、秘密値検出0、専用resource/PKI/port回収。revoke200は個別token失効の証明ではない |

## 自動検証

- 最終`make validate`、既存venvによる`make test`、`make test-plugin`: pass。make testのsandbox loopback検査1 skipは、その1件だけを権限付きで再実行してpass。
- 最終guard追加後の`make test-wp5-transport`: pass。Lua transport/bridge、runtime6、selector4、fixture11、flow10。
- 実OpenResty native probe: 実X509/cdata、PS256署名検証、元options/本文保持、重複送信拒否、header注入0。HTTP senderはmock、AS成功は直結v2で別確認。
- metadata証明書のfingerprintを設定hashへ追加。同じpathで証明書が変わるとconfigureはrestart-requiredに閉鎖する回帰検査がpass。
- Git対象173ファイルとprivate候補14件の照合で秘密値一致0。`.env`、`.generated`はGit外。

## プレビューと通常受入の残件

third-party CPのread-only diffはcreate11/update0/delete0。Service2、Route2、service plugin7のみ追加。foundation certificate/CA/global transportは不変。詳細とhashは[直結preview](third-party-wp5-transport-preview.md)を参照。

通常環境のapply/sync/up/realm更新は未実施。PR #21 merge後の仕上げでは、固定entity IDとレビュー済み11/0/0差分に限定するthird-party同期経路、既存realmのPS256 provider反映を追加する。未承認の同期と通常make upは閉鎖を維持する。WP3 #9の通常migration（preview create6/update0/delete13）と、WP5の通常統合は[通常統合プレビュー](third-party-wp5-normal-preview.md)でまとめてレビューする。

独立レビューは、通常state/runtime/selectorをfixture担当Luna、transport/bridge/guard snapshotをruntime担当Lunaが読み取り専用で実施した。blocking指摘0。metadata fingerprintの指摘はRoot修正・回帰テスト・再レビュー済み。2 workerのstatus初期化と全workerへのHTTP配信は区別する。supervisorは呼出し元のlistener設定を確認するが、起動済みcontainerのlistener実設定は通常統合で照合する。

PR #21は利用者がmerge済み。次の順序: 通常同期の仕上げPRレビュー・merge → 通常migration preview確認 → mainで独立positive/negative → IssueへTechnical Completion Report → 利用者受入・close。Issueを自動closeしない。

## 証跡の保存

[直結preview](third-party-wp5-transport-preview.md)、[observer preview](third-party-wp5-observer-preview.md)、[再入preview](third-party-wp5-reentry-preview.md)にsanitized要約とreceipt hashを記録する。raw token/JWT/jti/body/cookie/password/秘密鍵/完全certificate/log/private sourceはGit・PR・Issueへ載せない。一次receiptとRoot proofはGit外で保持する。
