# Luna / xHigh向けEnhancement開発移譲契約

開発担当はIssueを1つずつ実装し、受入条件と証跡を対応付けたPRを提出する。現在のWP2担当設定は、利用者の最新指示による **Codex / gpt-6-luna / xhigh**。WP1はLuna / Highで実施した。個別の開始・環境変更承認はIssueへ記録する。

## 基準と現在地

- 対象: [Epic #6](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/6)、WP1〜WP6（#7〜#12）。
- 設計baseline: [PR #5](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/pull/5)、main merge commit `bc4a063df75ac28d29c33299b90deac3bd1ebe98`（レビュー対象head `3a41ebceb9183f80702c1f898c83991d102fe61e`）。
- 2026-10-02: Design ownerレビューはmerge blocker 0。`make validate`、`make test`、差分空白検査、変更Markdownのローカルリンク、図JSON解析と4図PNG目視が完了。
- PR #5は初回の自動承認レビュー拒否後、利用者が本PR限定の規則の例外を明示承認し、2026-10-02にmergeした。設計・WP1実装・修正のPR #13／#15／#16／#17は利用者がmainへmerge済み。PR #5の例外を他PRへ適用しない。
- main `4ce796d`で独立検証した両foundation diff=0、既存14 entity不変、API共有CA再利用・schema hash照合、19 tests、main CIはpass。[Issue #7](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/7)にTechnical Completion Reportを記録し、利用者がWP1受入・close・WP2着手を承認した。利用者の代理close承認に基づき#7はclosed。[Issue #8](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/8)をLuna / xHighで開始する。
- 実TLS、JWT署名、Keycloak observer build、transport lifecycle、introspectionの実行証跡は今回取得していない。

着手前にremoteを同期し、設計合意・依存WP受入・開始条件をIssueで確認する。baselineの差分があれば、再確認してからbranchを作る。設計はADR 0009〜0014、実装要件、DP0と[WP1詳細設計](third-party-foundation-design.md)を正本とする。Workerは方式を選び直さない。

## 成果と範囲

顧客向けに、UI → 3rd Party Gateway → API Gateway → Upstream APIを実行できるデモを作る。別々のKonnect CPで2つのGatewayを管理する。Kongは3.16.0.0、Keycloakは26.7.4を固定し、対象architectureとimage digestを証跡に記す。

| 区分 | 必須の結果 |
|---|---|
| P0 | Route Aの`tls_client_auth`、Route Bの`private_key_jwt`、AS全back-channelとAPIへのmTLS、token有効性とPoP、資格情報の非漏洩 |
| P1 | PAR、PKCE S256、introspection/active、issuer/audience/scope、header限定、refresh等の対象シナリオの結果 |
| D | logout/reset後、別Route・別userで新しい認可フローを再実行できる |
| F/任意 | DPoP、開始CSRF追加防御、iss欠落guard、厳格な個別失効証跡。未対応を開示する |

完全FAPI適合、認定、本番保証、失効反映SLAは完成条件にしない。P0失敗をP1/Fの扱いへ変更しない。P1に新規customが必要と判明したらDesign ownerへ戻す。

## Issueと開始条件

| Issue | 実装branch | 開始条件 | 完了時の判定 |
|---|---|---|---|
| [WP1 #7](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/7) | `feat/wp1-dual-gateway-foundation` | 設計merge・schema分担合意 | 基盤、schema、CI、plan/diff証跡 |
| [WP2 #8](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/8) | `feat/wp2-keycloak-clients` | WP1受入 | introspection事前確認、realmとAS negative |
| [WP3 #9](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/9) | `feat/wp3-resource-server` | WP2受入・事前確認pass | 両Routeに共通のRS検証 |
| [WP4 #10](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/10) | `feat/wp4-upstream-verifier` | WP1受入 | trusted Gateway peerと転送certの再検証 |
| [WP5 #11](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/11) | `feat/wp5-third-party-transport` | WP3受入・DP0合意。冒頭spike pass後に本体 | AS mTLS、signer、入口preflight |
| [WP6 #12](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/issues/12) | `feat/wp6-demo-evidence` | WP4とWP5受入 | UI、E2E、negative、reset、再現手順 |

WP4はWP1受入後に別branchで進められる。依存受入と実装着手承認をIssueに記録する。移譲準備は、実際のWorker起動や実装着手を意味しない。

2026-10-02、利用者の「良いです。進めてください。」を設計補足の合意とWP1実装着手の指示として記録した。最初のWorkerはLuna / HighでWP1だけを担当した。初回は合意済み設計branchをbaseにしたが、設計merge後はPR #15で実装をmainへ載せ直した。以後の修正PRは最新mainをbaseにする。環境変更とWP2以降の着手承認は別に扱う。

同日、利用者の「承認しますが、Luna | xHighで実施してください」をWP1受入・#7 close・WP2コード/fixture/検証計画/PR準備への着手承認として記録した。WP2のbaselineはmain `4ce796d08c02b623d71c8ad10d245a61af70c83a`。Docker build/up、realm適用、runtime投入、通常入口開放は、具体的previewと別承認の後に行う。

## WP1: 基盤・schema・CI

変更候補は`infra/konnect.tf`、`infra/outputs.tf`、`infra/variables.tf`、`docker-compose.yml`、`.env.example`、PKI/runtime生成script、`scripts/deck.sh`、`scripts/plugin-schema.sh`、`Makefile`、GitHub Actions、custom schema、静的test。

| 受入ID | 合格条件と証跡 |
|---|---|
| WP1-CP | 既存CP/DPのTerraform addressを維持し、3rd Party CP、独立DP鍵・証明書とlocal sensitive fileを追加。sanitized planは追加基盤だけ。既存resourceのdestroy/replace、意図しない更新は0 |
| WP1-SELECT | `GATEWAY=api|third-party`をdiff/sync/schema操作で必須にする。未指定・不正値・ローカルmapping不整合は認証/通信前に非zero。実CP名はread-only照会で確認し、不一致なら後続操作を停止。mockと両foundation live diffを別々に記録 |
| WP1-PKI | metadata、API server、introspection、upstreamの鍵を用途別に分離。API server certに`kong-api`とhost検証用SANを含める。新材料はGit外、read-only mount。生成済み材料を意図せず上書きしない |
| WP1-SCHEMA | 詳細設計の型/default/固定値に従いtransport schemaとbridge delegate enumを準備。third-party CPの両schemaを内容hashまで照合し、schema syncは別承認。API用stateに両custom Entityなし。legacy登録schemaを削除せず、登録をDPロード成功と説明しない |
| WP1-STATIC | `make validate`が両foundation state・compose・schemaを検証。third-party両plugin必須/API両plugin禁止、bootstrap、third-party foundationのglobal transport Entity有効1件、固定Route manifestとidentityのpositive/negative検査。実Route entity一致はWP5 |
| WP1-STAGE/TARGET | 詳細設計のstage必須、state ownership、CP照合順を検証。WP1はfoundationだけをdiffし、API既存v1 entityのupdate/delete=0。未完成runtimeやタグ範囲改変は拒否 |
| WP1-SCHEMA-DRIFT/IDENTITY | 両schemaの欠落/drift、UUID/client ID/cert pathの入替・重複、CP/秘密鍵mountの混用を拒否 |
| WP1-CA-REUSE | API foundationは新Certificate 2件だけ。既存CA333のID・tags=`[fapi2-demo]`・公開DERをrole入力とread-only照合し、不一致／欠落／不正応答ならdecK起動前に停止。CAをcreate/retagせず、既存update/delete=0。third-party CAは別CP内で従来どおり管理 |
| WP1-CI | credential不要のPR checkで`make validate`と`make test`が成功。既存Trivy参照を公式`v0.33.1`のcommit `b6643a29fecd7f34b3597bc6acb0a98b03d33ff8`へpinし、実行結果を確認。scanを外したり、失敗を成功に変換しない |
| WP1-SECRETS | `.env`、`.generated`、state/plan、秘密鍵/証明書、token/licenseをGitへ追加しない。PR差分とignoreを確認し、値を表示せず結果だけ記録 |

runtime stateはAPIがWP3、third-partyがWP5で完成させ、foundation全entityを同一ID/タグで包含する。APIの既存CA333は`[fapi2-demo]`のままruntimeへ含め、migrationでも削除・再作成しない。WP1時点で通常入口/UIは閉鎖を維持する。仮handlerを作らず、未実装transportのロードを外して起動を通さない。新CP作成・schema登録の承認がない場合、live diffはnot_run、WP1の完全受入は保留とする。

## WP2: Keycloak clientsとintrospection

変更候補は`keycloak/realm-template.json`、realm生成/sync script、PKIのclient登録値、test fixture。現行clientを新IDに置き換え、API Gateway introspection専用clientを追加する。

- 最初の独立判定: **RS-INT-AUD-02**。Route A/Bそれぞれ実certificate-bound tokenを取得し、専用clientのmTLS introspectionで`active=true`、一致する`cnf`、2 audience、`scope`、namespaced claimを確認する。tokenはmemory内で扱い、公開はsanitized結果だけ。
- **RS-INT-AUD-01**: 有効な署名・時間・session・bindingと`fapi-demo-api`を維持し、introspection audienceだけを欠くfixtureで`active=false`。他の失敗原因との混同を防ぐ。
- 3 client、PAR強制、PKCE S256、code lifetime 60秒以下、redirect URI、PS256と公開JWK、refresh rotation切替を宣言的に再現する。
- **A-CERT-01/02、B-AUD-01、B-JTI-01、B-CERT-01**を新client IDで再実行する。AS拒否と送信guard拒否を別fixtureにする。
- 必須claimが欠ければWP3へ進まず`needs-design`。audience checkの無効化やbearerへの独断切替はしない。

Keycloak 26.7.4の[公開source](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java)は、認証したintrospection clientのaudience照合と`cnf`保持を示す。audienceが元tokenに存在すれば、その値を判定に使う。RS-INT-AUD-01ではAPI audienceを残し、同一realm/client/sessionのpositive referenceと比較する。server-wideのbypassと、[client属性](https://github.com/keycloak/keycloak/blob/26.7.4/server-spi-private/src/main/java/org/keycloak/protocol/oidc/OIDCConfigAttributes.java) `allow.token.introspection.without.audience.check`の両方を無効のまま検証する。mapperはintrospection responseにも適用されるため、namespaced claimの宣言だけで返却成功と推定せず、実応答を確認する。

組込み[FAPI 2 profile](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/resources/keycloak-default-client-profiles.json)は`secure-client-authentication-assertion`を含む。[同executor](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/executor/SecureClientAuthenticationAssertionExecutor.java)はback-channelでissuer URLへのaudience一致を要求する。B-AUD-01はprofileの適用を確認してから、有効なgrantと署名を保ち、audだけtoken endpoint URLへ変更する。認可fixtureはprofileのconsent要件も維持する。sourceの実装確認はASの拒否応答の証跡を代替しない。

namespaced claimのmapper設定ではURI内のdotをescapeする。Keycloakの[claim path処理](https://github.com/keycloak/keycloak/blob/26.7.4/server-spi-private/src/main/java/org/keycloak/utils/JsonUtils.java)はunescaped dotを階層の区切りとして扱い、escapeを除いてJSON keyへ写す。templateのescape表現を維持し、実token/introspectionでは`https://fapi-demo.example.com/department`と`https://fapi-demo.example.com/route`の完全一致keyを検証する。

## WP3: API Gateway Resource Server

変更候補は`kong/api-gateway.yaml`、API用runtime/TLS設定、RS test harness。`auth_methods=[introspection]`、header only、active確認、cache無効、strict mTLS PoP、issuer/audience/scopeを固定する。

- exact runtimeで`tls-handshake-modifier`、OIDC（priority 1050）、`tls-metadata-headers`（996）のschema/phase/priorityと設定受理を記録。master sourceやmock schemaだけで完了しない。
- **POP-01/02/03**でcertなし・別Route・binding不一致を拒否。自己署名certのCA外という属性だけを拒否理由にしない。
- **RS-QUERY-01**に加えてbody tokenも拒否。**RS-AUD-01、RS-SCOPE-01、ERR-01、RS-VALID-01、TLS-RS-01**で認可とTLSを検証する。
- **HEADER-CERT-01**でclient供給cert headerを上書きし、証明書欠落時にはUpstreamへ到達させない。`X-Demo-*`はclaim由来、Cookieとclient供給`X-Fapi-*`は除去する。
- Gatewayは専用upstream certで接続する。JWT再検証に必要なAuthorizationだけをUpstreamへ転送する。
- tag限定のsync前diff、承認後sync、sync後diff=0。**RS-REVOKE-01**は任意、未実施を失効保証に読み替えない。
- **WP3-MIGRATION**: API runtime stateへfoundationを包含し、旧v1 entityの除去を独立previewする。入口停止、旧sessionと復旧手順を確認してから適用する。WP1のcreate-only基盤受入へ削除を混ぜない。

## WP4: Upstream API

変更候補は`pop-verifier/app.py`、API用runtime環境、`tests/test_pop_verifier.py`。

- TLS peerのchain検証に加え、API Gateway専用upstream certのidentityを固定して照合する。同じ開発CAのRoute certだけでは通過できない。
- trusted peer確認後にだけURLエンコードPEMの`X-Client-Cert`を読み、leaf DERから計算したthumbprintと`cnf`をconstant-time比較する。欠落・不正PEM・複数/曖昧な値・不一致は`401 invalid_token`。
- JWT署名、PS256のみ、issuer、`aud=fapi-demo-api`、exp/nbf、scopeを再検証する。`azp`を固定2 client IDへ照合してA/Bを導出し、不明な`azp`やheaderによるRoute偽装を拒否する。
- unit testはAPI peer不一致、転送cert欠落/不正/binding不一致、aud/scope/algorithm/azpの異常と正常系を確認。**UPSTREAM-01**は実TLSで直接接続拒否を示す。
- sanitized responseに`azp`、Route、token binding、転送client cert thumbprint、再検証booleanを含める。Gateway→Upstreamのpeer thumbprintと混同しない。**LEAK-01**でtoken/cookie/assertion/秘密鍵/完全certを返さない。
- この変更はWP3-MIGRATIONで導入するAPI verifier更新であり、既存v1証跡・guardを弱めたり置き換えたりしない。Route A/B証明書を再生成せず、旧runtime entityの除去・切替はWP3の独立previewと受入に従う。WP4のfresh TLS harnessはAPI peer pinとJWT verifierの動作を検証し、Keycloak発行tokenやGateway統合の証明とは扱わない。

## WP5: spike、transport本体、integration

同じIssue内を次の順で進める。5aの結果をDesign ownerへ報告してから5bへ進む。Lunaは固定契約に沿って実装し、不成立を設計へ戻す。

| 段階 | 成果と継続条件 |
|---|---|
| 5a | **AS-MTLS-OBS-01**。exact Keycloak test-only observer build/hook、peer chain、有効/未信頼/期限切れcert、certなし対照、1:1相関、stock PAR/revoke実署名claimとsession/logout fixtureを検証。不成立なら本体実装前にneeds-design |
| 5b | `fapi-as-mtls-transport` handler、既存bridge signer APIとdelegate mode。inventory完全一致、固定mapping、Route/metadata cert、context/epoch、POST再送禁止、redirect拒否、cdata lifetime、失敗時閉鎖、restartで設定反映 |
| 5c | `kong/third-party-gateway.yaml`、全worker preflight、実TLS/署名/lifecycle/並行/background/thread証跡、既存bridge回帰とexact image drift確認 |

- **B-TRANSPORT-01**: PAR、code exchange、refresh、refresh/access revokeを別operationで判定。Route B peerとPKJWT、issuer文字列aud、PS256、TTL条件を確認。token/refreshのsignerは送信時に呼ぶ。PAR/revokeのstock claimを修正しない。
- **AS-META-MTLS-01**: A先行/B先行、cold cache、stock discovery/JWKS、bridge discovery、background/threadの専用metadata certを実AS peerで確認。warm no-fetchはskip。
- **AS-TRANSPORT-GUARD-01**: 未知URL/HTTP/外部origin/3xx、context/signer/epoch不足、cert不一致、期限不足をnot_sentで拒否。同一POSTはfresh assertionでも拒否し、別tokenの2 revokeは許可。
- **AS-TRANSPORT-LIFECYCLE-01**: 全worker実ロード、wrapper1回、registry epoch、configure前/invalid/nil、同一再通知、変更/restart、他plugin非AS通信を確認。transportだけ/両plugin欠落で入口/UIを閉じ、Route A metadata未送信を証明。
- **WP5-BOOTSTRAP**: 設定受領前もCP通信だけを許可し、public/internal AS originへの到達とstock background/metadata送信を遮断する。UI停止だけでpassにしない。全workerのgeneration/ready/configを照合後に通常入口を開き、欠落・再起動・変更で閉鎖する。実証できなければneeds-design。
- **A/B-PAR-01、B-PKJ-01、PAR-01/02、PKCE-01、A/B-CNF-01、HDR-01、TLS-01、ISS-01、META-01/02、RT-01、RT-ROT-01、B-SPOOF-01、B-AUD-02、REDIR-01**も実行する。TLS-02はP1対象として証跡を取得する。
- **B-AUD-01/B-JTI-01**のdirect AS negativeは送信guardと分ける。signature不正、期限切れ、誤aud、同assertion replayを検証し、どの層が拒否したか記す。
- 通常デモは標準Keycloak imageでpositive flowを再確認する。test-only計測image/harnessを通常経路に入れない。logout revoke失敗時はcertなしで再送せず、対象demo user限定resetへ進む。

sourceで確認できるhook候補は[TransactionalSessionHandler](https://github.com/keycloak/keycloak/blob/26.7.4/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/TransactionalSessionHandler.java)、TLS peer取得は[QuarkusHttpRequest](https://github.com/keycloak/keycloak/blob/26.7.4/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/QuarkusHttpRequest.java)。buildと全inventoryへの到達はspikeで証明する。`request`モードはcertなし接続も許容するため、AS全入口のcert必須とは説明しない（[26.7.4 TLS guide](https://github.com/keycloak/keycloak/blob/26.7.4/docs/guides/server/mutual-tls.adoc)）。

## WP6: UIと受入証跡

変更候補は`ui/`、browser E2E/negative harness、README、[顧客向け説明](third-party-demo-explainer.md)。

- **A/B-E2E-01、CLAIM-01、HEADER-01、LEAK-01、ALG-01**を自動化または文書化したbrowser evidenceで判定。P0 transport/PoPの必須試験をブラウザー手順だけで代用しない。
- **RESET-01、LOGOUT-A/B-01、SWITCH-01**: 両Routeからresetし、旧sessionを再利用せず、別Route・別userで新しい認可フローと期待claimを確認する。手動resetは対象demo userに限定する。
- UIのthumbprintは3rd Party→API Gateway区間を示す。client認証方式は`azp`の固定mappingから導き、呼出し側headerを信用しない。
- clean checkoutから秘密材料生成、2 CP/DP、Keycloak、Upstream、preflight、UI起動、両Routeを、承認ゲート込みのREADMEで再現する。
- 全P0/P1/Dの結果とF/N/A理由を統合する。stock/custom/未対応/未検証、AS listener制約、resetと失効の違いを顧客向け説明に反映する。

## 証跡・PR・受入の共通契約

PRは`Refs #<issue>`を使う。自動close語は使わない。1 Issue、1 branch、1実装PRを基本とし、別sessionのReviewerがレビューする。Lunaはmergeしない。

| 受入ID | 実装file/symbol | シナリオ/fixture | 層 | 結果 | 証跡要約 |
|---|---|---|---|---|---|
| 対象ID | 対象箇所 | positive/negative | static/unit/runtime/browser | pass/fail/not_run/skip | sanitizedな結果とローカル証跡path |

`make validate`、`make test`、Issue固有test、該当plan/decK diff、CI結果、設計逸脱、制約をPRに記す。evidenceは`.generated/evidence/<scenario-id>.json`へ保存し、Git外に置く。公開はHTTP status、thumbprint先頭12文字、alg、azp、boolean等に限定する。raw JWT/jti/token/cookie/code/assertion/body/秘密鍵/完全cert/private sourceは公開しない。

AS証跡はrequest ID、method、queryなしpathで実Keycloak observerへ1:1 joinする。peer存在だけでverifiedとしない。PKIX/期限/EKU、listener/truststore receiptとTLS negativeが揃うことを確認する。送信前拒否はAS行なしのnot_sent、cacheによる取得省略はskipとする。

環境変更は、対象、sanitized preview、影響、承認範囲をIssueに記録してから行う。WP1の6件apply、2schema登録、7件foundation createの承認・実施結果はIssue #7へ記録済みであり、別の操作へ承認を拡張しない。Docker起動、realm更新、runtime sync、入口開放は未実施。必要な変更が承認範囲にない場合は具体的previewを用意して報告する。

Design ownerは実装merge後のmainで主要positive/negativeを独立再実行し、Technical Completion ReportをIssueへ記録する。利用者が受入結果を記録し、Issueをcloseする。設計ready、PR merge、mock成功をruntime完成と同一視しない。

## WP1の初回開発指示（履歴）

> Codex / gpt-6-luna / highでWP1 #7のみを担当してください。remoteと必須Vault文脈を読み、PR #5のmerge、ADR 0013の分担合意、Issueの開始状態を確認してください。`feat/wp1-dual-gateway-foundation`で基盤・schema・CIを実装し、既存CP/DP resourceを保全してください。通常入口は閉鎖を維持し、transport handlerは実装しません。未承認の環境変更は行わず、必要なpreviewと承認対象を具体化してください。WP1受入IDの対応表と検証結果を付け、`Refs #7`のPRを提出してください。設計不成立はDesign ownerへ戻し、merge/Issue closeは行わないでください。

WP1の最初の成果は詳細設計のresource/output/identityとfoundation stateである。`STAGE=foundation`で両diffを取得し、runtimeの空stateを作って旧v1を削除しない。schemaの登録とhandler実装、CPのmetadata照会と通信前入力検査を分けて報告する。

## WP2の開発sessionへ渡す指示

> Codex / gpt-6-luna / xhighでWP2 #8だけを担当する。main `4ce796d`をbaselineにremoteと必須文脈を確認し、`feat/wp2-keycloak-clients`で最小のrealm/client候補とRS-INT-AUD-02/01 fixture・harnessを準備する。新client IDと既存Route certificate subjectを明示対応し、introspection専用identityと両audienceを維持する。意味あるnegative testsと隔離環境previewを提示し、未承認のDocker/realm/runtime操作は行わない。mock/static成功は実TLS/token成功に読み替えず、必須claimが欠けたらDesign ownerへ戻す。PRはRefs #8、受入ID・検証層・証跡・未検証を明記する。WP3以降と通常入口を開始しない。

## 参照

- [実装要件とシナリオ](third-party-fapi2-requirements.md)
- [Conformanceと優先度](third-party-fapi2-conformance.md)
- [Delivery plan](third-party-delivery-plan.md)
- [DP0 transport契約](third-party-as-mtls-transport.md)
- [AS peer証跡契約](third-party-as-peer-evidence.md)
- [ADR 0013: schemaと受入分担](../decisions/0013-work-package-schema-and-acceptance-boundaries.md)
- [ADR 0014: APIの既存CA再利用](../decisions/0014-reuse-existing-api-ca.md)
- [WP1詳細設計: address、PKI、identity、state、schema](third-party-foundation-design.md)
- [WP2隔離検証preview](third-party-wp2-validation-preview.md)
