# WP5実装・受入対応表

## 判定（2026-10-05）

顧客向けデモのAS側の必須機能と、issuer不一致拒否・refresh rotation・PAR parameterは隔離環境で動作した。main `f8c3a8f`で通常環境への適用とA/B統合確認もpassした。重い網羅検証の省略は2026-10-05に利用者が承認した。代表redirect負例もpass。metadataのrevocation通知URL差分はADR0021の既知差分として利用者が受け入れた。PR #25 merge後のmain `72a6426`で証跡を照合し、WP3 #9・WP5 #11を受入確認完了としてCloseした。

目的は、顧客要件をなるべくKong標準機能で実装して実演すること。本番FAPI 2.0完全準拠、認定、iss欠落guard、開始CSRF追加防御、DPoP、厳格な個別失効SLAは今回の完成条件に追加しない。stock PAR/revoke本文を維持し、PARのclient_id欠落はRFC 9126の既知gapとして開示する。

## 受入条件と証跡

`pass`は指定した検証層での成功。`partial`には未実行の部分が残る。unit/nativeの成功を実AS、通常hybrid DP、通常supervisor、main受入の成功へ読み替えない。

| 受入ID | 実装箇所 | fixture・層 | 結果・限界 |
|---|---|---|---|
| AS-MTLS-OBS-01 | test-only observer、stock fixture | direct TLS v3、再入r4、stock v15 / 固定image＋実AS | pass。TLS40/40、stock署名/PAR/session/logout、実peer join。計測imageは通常構成に入れない |
| A-PAR-01、B-PAR-01、B-PKJ-01 | third-party state、transport、bridge | 直結v2 / 固定Kong＋Keycloak | pass。A/B各PAR201→code200→callback302→session。AはTLS認証、BはPKJWT＋mTLS |
| A-CNF-01、B-CNF-01 | Route別AS identity | 直結v2 / 実AS token応答 | pass。code/refresh4応答のcnfが送信leafと一致。API側PoPはWP3証跡に加え、通常A/BのAPI応答でもbinding_verified=true |
| B-TRANSPORT-01 | transport全endpoint、bridge送信時signer | 直結v2 / 実AS observer | pass。BのPAR/code/refresh/access revoke/refresh revoke各1件。PKIX・期限・EKU・leaf照合、PS256/issuer文字列aud/TTL/jti判定 |
| AS-META-MTLS-01 | 専用metadata identity | 直結v2 / 実AS observer | pass（承認範囲）。fresh cacheのdiscovery2/JWKS1は専用peerで成功。全background/thread形態・全worker HTTP配信は受入ゲートから省略し、未網羅として記録 |
| META-01、META-02 | 固定issuer/endpoint、bridge discovery | unit、直結v2 | META-01 pass、META-02はrevocation URL差分あり。通常DPから実discoveryを取得して静的値/aliasと照合。revocation以外は一致。詳細は下記 |
| RT-01 | stock session/refresh | 直結v2 / 実user＋実AS | pass。隔離証跡に加え、通常A/Bでも300秒の期限後に保護GET200/binding_verified=true |
| RT-ROT-01 | realm rotation、stock session | 拡張flow v6 / 実AS＋stock session | pass。A/Bとも2回の期限後refreshが成功。最初の応答でtokenが変わり、2回目はその更新値を使ったことをworker共有辞書内の比較で確認。token/hash値は非公開 |
| PAR-01 | stock PAR設定 | 直結v2 / 実AS | pass（デモ動作）。PARより先の認可開始なし。RFC 9126適合はgapを維持 |
| PAR-02、PKCE-01 | stock PAR/redirect/PKCE | 拡張flow v6 / 最終wire＋browser | PAR-02 pass。両Routeのqueryはclient_id/request_uriだけ、nonceは64文字以下、callback URIは固定。PKCEはS256/challenge存在を確認。異なる開始要求のchallenge比較は未記録だが、2026-10-05の承認で今回の必須ゲートから省略 |
| B-AUD-02、B-SPOOF-01 | bridge、transport | unit/native、guard v3 / 実Kong worker | pass（範囲限定）。issuer文字列audの署名、header/query/body assertion偽装400。AS側wrong-audはWP2の証跡 |
| ISS-01 | stock callback処理 | 拡張flow v6 / 実Kong callback | pass。A/Bとも改変issを401拒否、同じ正規code/state/cookieの対照は302/session成立。code交換は各1回。iss欠落guardは作らない |
| AS-TRANSPORT-GUARD-01 | transportのform/identity/ledger/endpoint guard | unit/native＋直結v2 | pass（承認範囲）。既存unit/nativeの未知origin/HTTP/redirect/重複POST/変更hint同一token拒否、異なる2 revoke許可と実AS revoke成功を維持。再送・並行A/B負例の全組合せは省略 |
| AS-TRANSPORT-LIFECYCLE-01、WP5-BOOTSTRAP | Docker preflight、worker snapshot、local marker、supervisor | guard v3＋native起動preflight＋unit | pass（承認範囲）。隔離guard拒否/AS0、plugin欠落停止に加え、通常4 worker readiness・入口/UI公開・reload閉鎖を確認。全workerへの各HTTP case強制配信は省略 |
| HDR-01、TLS-01 | third-party Service/OIDC、API側WP3 | state validation＋実AS＋WP3 isolated | pass。設定/隔離証跡に加え、通常3rd Party→API→UpstreamでA/Bの署名・binding・claim/header一致を確認。偽装X-Demo headerの上書きもpass |
| REDIR-01 | 固定login/logout URI | state validation＋直結v2正常flow | pass（代表1件）。通常Route Aのcallbackへ外部login_redirect_uri、logoutへ外部logout_redirect_uri/post_logout_redirect_uriを指定しても、固定login/logout UIへ遷移。外部targetを追従せず。全parameter/Routeの網羅ではない |
| logout/reset、LEAK-01 | stock logout設定、bounded diagnostics、cleanup | 直結v2、guard v3 | pass（隔離範囲）。access/refresh revoke200、秘密値検出0、専用resource/PKI/port回収。revoke200は個別token失効の証明ではない |

## 自動検証

- 最終`make validate`、既存venvによる`make test`、`make test-plugin`: pass。make testのsandbox loopback検査1 skipは、その1件だけを権限付きで再実行してpass。
- 最終guard追加後の`make test-wp5-transport`: pass。Lua transport/bridge、runtime6、selector4、fixture11、flow10。
- 実OpenResty native probe: 実X509/cdata、PS256署名検証、元options/本文保持、重複送信拒否、header注入0。HTTP senderはmock、AS成功は直結v2で別確認。
- metadata証明書のfingerprintを設定hashへ追加。同じpathで証明書が変わるとconfigureはrestart-requiredに閉鎖する回帰検査がpass。
- Git対象173ファイルとprivate候補14件の照合で秘密値一致0。`.env`、`.generated`はGit外。

## 通常統合と受入の残件

利用者がPR #21〜#23をmergeし、具体的な宛先・削除範囲を承認した後、API create6/delete13とthird-party create11を適用した。main `f8c3a8f`で通常A/Bのログイン、API200、claim/header一致、偽装header上書き、期限後refresh、stock logoutを確認した。UIはHTTPS200。4 worker readiness後の公開と、reloadによるsupervisorの入口/UI閉鎖・DP停止もpassした。確認後は同じ構成で監視付きデモを再開した。

通常実行ではnative Kong 3.16 base＋main plugin sourceのread-only mountを使う。公開multi-architecture imageとclean checkout再現は未受入。APIの残diffはcache_tokens_saltの1 updateのみで、cache_tokens=false。再syncはしない。

受入上の未網羅部分は、全workerへの全HTTP負例配信、全background/thread形態、fresh assertion等の負例の全組合せ、別認可開始間のPKCE challenge比較、外部URL誘導負例と通常metadata endpoint対応表。既存unit/native/隔離証跡の成功範囲は上表のとおりで、通常E2Eの成功から未実行項目をpassとしない。

## 2026-10-05の受入範囲合意

利用者が省略案を承認した。今回のデモ受入では、全workerへの全HTTP負例の強制配信、全background/thread形態、再送・A/B並行負例の全組合せ、別認可開始間のPKCE challenge比較、通過済み隔離matrixの全面再実行を必須ゲートにしない。実装・設定・既存の拒否検証は維持し、未網羅を記録する。代表的な外部redirect負例1件と、通常metadata endpoint照合は残す。

metadataの実取得ではissuer、authorization/end-session、token/PAR/JWKSとtoken/PAR mTLS aliasは期待どおり。revocationだけは通常値・aliasとも公開originを通知し、静的設定の内部originとは異なる。Keycloak 26.7.4の`OIDCWellKnownProvider`はrevocationをfrontend URIから組み立て、mTLS aliasへ同じ値をコピーする（source lines 206–211 / 342–345）。内部originのrevoke成功は直結・通常logout証跡で確認済みだが、META-02の文字列完全一致はpassとしない。runtime設定の変更は行っていない。

redirect確認時に通常の認可開始controlもHTTP500で停止した。client keyのPEM読み込み失敗はrestartでは回復しなかったが、同じ構成のTP-only force-recreate→CP再取得→全worker gateで復旧した。復旧後の代表redirect負例とA/B login/API200/binding/signature/header/spoof/logoutがpass。原因は保存済みDPデータのVault参照解決に関連する可能性があるが、再作成による回復だけを事実として記録し、根本原因は断定しない。


通常証跡はGit外の`wp5-normal-flow-route_a.json`、`wp5-normal-flow-transport_route_b.json`、`wp5-normal-supervisor-reload.json`。A/Bのreceipt SHA-256は[引き継ぎ](../session-handoff.md)に記録した。通常ASにはobserverを入れず、AS peerとassertion/rotationの詳細証明には通過済み直結v2/v6を使う。通常refresh後200は正常動作の証明であり、新たなrotation内部観測ではない。logout成功も個別token失効SLAの証明ではない。

[ADR0021](../decisions/0021-wp5-revocation-metadata-gap.md)に従い、現行の静的内部revocation URLを維持し、通知URLとの不一致を既知差分として受け入れる。2026-10-05の利用者merge・受入指示に基づく判断で、META-02を完全一致passへ読み替えず、追加のKeycloak実装はしない。

追加証跡: Git外`wp5-final-two-checks-20261005.json`（SHA-256 `e23fdc0e40b51dabc3a04f2abe3434e9c0c4a8c6b72e2f8c4a1920cd0f84456e`）。redirectはpass、metadataはrevocation差分ありのため全体ok=false。復旧A/Bは`wp5-normal-recovery-route_a-20261005.json`（`1f715d179d1f5bd39ad47fd2ed8c7f30606542218ed7ed858aa91216adf436ac`）、`wp5-normal-recovery-transport_route_b-20261005.json`（`5f1ef70faf861a96d4dbaf02d57ef161b2a6feb7204c07de2071604de793f74d`）。以前のrefresh証跡は上書きしない。

Issue #9/#11へ最終Technical Completion Reportを記録し、利用者の指示に基づき受入確認・Close済み。受入時の現行全worker readinessとUI HTTPS200もpass。通過済みmatrixは再実行せず、一次receiptのhash/結果/private modeと、metadataの差分が承認対象だけであることを確認した。最終受入receiptはGit外`wp5-final-acceptance-20261005.json`、SHA-256 `4843f9d7a11e7e3a0655bc3bf0993589e7b393a2293281bfe24d84a32228eec3`。次の実装packageはWP6 #12（UI表示、reset/切替、再現手順）。

## 証跡の保存

[直結preview](third-party-wp5-transport-preview.md)、[observer preview](third-party-wp5-observer-preview.md)、[再入preview](third-party-wp5-reentry-preview.md)にsanitized要約とreceipt hashを記録する。raw token/JWT/jti/body/cookie/password/秘密鍵/完全certificate/log/private sourceはGit・PR・Issueへ載せない。一次receiptとRoot proofはGit外で保持する。
