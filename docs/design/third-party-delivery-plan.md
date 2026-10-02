# 3rd Party経由FAPI 2.0デモ Delivery plan

## この文書の目的

[3rd Party経由FAPI 2.0デモ要件](third-party-fapi2-requirements.md)を実装するための、作業分割、役割分担、検証方法を定義する。各Work package（WP）は、GitHub Issueとして起票する作業契約の原案である。優先順位は[ADR 0011](../decisions/0011-customer-demo-scope.md)に従い、P0（顧客必須）、P1（標準機能の追加価値）、D（デモ運用）、F（将来対応）を混同しない。完全適合を完了条件にしない。

## 役割

| 役割 | 担当 | 責務 | してはならないこと |
|---|---|---|---|
| Design owner | Labs（設計session） | 設計PR、Issue起票、Issue間の依存管理、merge後の独立検証、Technical Completion Reportの記録 | 実装PRを自分で作る |
| Worker | 開発session（Issueごとに1つ） | Issue単位でbranchとPRを作る。受入条件ごとの証跡をPRへ添付する | 設計判断の変更（必要ならIssueへ質問として戻す）。merge。利用者の承認がないlive変更 |
| Reviewer | Workerとは別のsession。可能なら別のprovider/model | PRを、Issueの受入条件、conformance文書の該当行、security checklistに照らしてレビューする | コードの修正（指摘に留める）。merge |
| 利用者 | 依頼元 | live変更の承認、PRのmerge、受入結果の記録、Issueのclose | — |

### live変更の承認ゲート

repositoryの`AGENTS.md`に従い、`terraform apply`、`deck gateway sync`、Dockerの変更には利用者の明示的な意図が必要である。WorkerはPRへ`make plan`と`make deck-diff`の出力（secretを除いたもの）を添付し、利用者の承認後にだけ適用する。利用者がWPの着手時にlive変更を包括的に承認した場合は、Issueへその旨を記録する。

## 作業の流れ

1. Design ownerが設計PRを作成し、利用者がarchitectureと未決事項をレビューしてmergeする。未対応の開始CSRF/iss欠落等は将来対応として開示する。今回の開発ゲートに専用のgap受容を設定しない。
2. Design ownerがDP0でP0の補完契約を確定する。Epic/WPのIssue起票・ready化は設計merge後に行い、WP5はDP0成果の合意前にreadyにしない。DP1は追加候補の調査であり、必須デモの完了を止めない。
3. WorkerがIssueを1つ取り、`feat/<wp>-<slug>` branchで実装し、`Refs #<issue>`付きのPRを作る。PRはIssueを自動closeしない。
4. ReviewerがPRをレビューし、PR commentに判定（approve / request changes）と指摘を残す。
5. 利用者がPRをmergeする。
6. Design ownerがmain上で独立検証を行い、IssueへTechnical Completion Report（成果、証跡、依頼元の確認手順、制約と残リスク）を記録する。
7. 利用者が受入結果を記録し、Issueをcloseする。不合格なら`status:needs-fix`へ戻す。

## Design packages（Design ownerのタスク）

### DP0: AS全back-channelのmTLS補完契約（P0、設計PR #5 merge済み・runtime未受入）

**担当はDesign owner。Workerへ方式選択を任せない。** 成果は[DP0契約](third-party-as-mtls-transport.md)と[ADR 0012](../decisions/0012-third-party-as-mtls-transport.md)。専用transport plugin + bridge送信時signer delegateを選択し、専用metadata cert、endpoint mapping、retry/redirect拒否を固定した。exact image bytecodeのmock probeは42件passだが、実TLS/Keycloak/lifecycle受入ではない。以下は本DPの調査・契約項目であり、runtime確認はWP5へ分ける。

- exact Kong 3.16.0.0 imageのオフライン確認で、Route A/Bとstock/bridgeが発生させるAS requestをinventory化する。PAR/token/refresh/revoke、discovery/JWKS、必要なuserinfo等を含める（現inventory外は拒否）。Keycloak 26.7.4のdiscovery値はWP5のMETA-02で確認する。
- 標準設定でcertが送れる呼出しを先に確定する。不足部分は専用transport decoratorと既存bridgeの限定変更を採用し、**実際の送信時**のPKJWT生成とmTLS transportを両立する拡張点を確認する。PAR/revokeにtoken用header注入がそのまま効くとは推論しない。
- 補完契約には、hook/module/API、endpoint/alias、cert選択・秘密鍵取得、issuer audience、一回限りのjti、送信時TTL、cache/cold start、失敗時のfail closed、upgrade drift検出、必要plugin設定を記載する。公開docsにprivate source原文を載せない。
- metadataの共有cacheでは専用certを使うと固定した。bridge独自discoveryがserver-only HTTPSのまま残らないようにする。
- Keycloakの`request`モードでcertが提示・検証される一次取得元を[test-only Keycloak observer](third-party-as-peer-evidence.md)へ固定する。Gateway transport（冒頭direct spikeではharness）生成IDで各operationへ1:1 joinし、AS-MTLS-OBS-01をWP5冒頭のspikeにする。browser HTTPSと、AS全入口でのmTLS強制がないという制約を維持する。
- 全P0を満たせない場合は、別transport adapter等の代替をDesign ownerが設計PRで再提案する。Workerがserver-only HTTPSへ下げたり、既存bridgeの単純移設で完了としたりしない。
- **完了条件**: 技術確認結果、補完契約、B-TRANSPORT-01/AS-META-MTLS-01のfixtureと証跡形式、ADR/要件/WP5/図の整合がレビュー可能な設計差分に揃う。設計合意・merge前にWP5をreadyにしない。runtime確認に必要な環境変更は別途live承認を得る。

### DP1: DPoP追加候補の可否・工数（F）

RS側stock検証とclient側proof生成を分け、Keycloak対応、nonce、replay、mTLS transportとの共存、追加client/BFF/customの要否を調べる。追加経路と検証案を提示するまでが設計タスクであり、実装開始や必須mTLS経路の置換は含めない。

## Work packages

Epic #6とWP #7〜#12はmerge前に起票済み。設計とWP1実装・修正のPR #5／#13／#15／#16／#17は利用者がmainへmerge済み。[ADR 0014](../decisions/0014-reuse-existing-api-ca.md)の既存CA再利用を反映したmain `4ce796d`で両diff=0と既存entity不変を独立確認し、利用者がWP1受入・#7 close・WP2着手を承認した。[Luna / xHigh移譲契約](third-party-luna-handoff.md)に従いWP2 #8を開始する。環境変更は具体的preview後の別承認。最終runtime stateはAPIがWP3、third-partyがWP5で完成させる。

依存関係: WP1 → WP2 → WP3 → WP5 → WP6。WP4はWP1の後、WP3と並行して進められる。**DP0 → WP5**も必須。DP1は別枠。

WP2のPR #18では、利用者が具体的previewの隔離runtimeとcleanupを承認し、[実token/AS試験9結果](third-party-wp2-runtime-evidence.md)を独立実行して成功した。途中のfixture/harness失敗も保持した。PRレビュー・利用者merge・main独立検証・利用者受入は未完了であり、WP3へはまだ進まない。

### WP1: 2つのGatewayの基盤

- **範囲**: Terraformで3rd Party用のKonnect control planeとdata plane certificateを追加する。composeを`kong-api`と`kong-third-party`へ分ける。開発PKIに新しい鍵材料（専用3rd Party metadata client、API Gateway server TLS、introspection client、upstream client）を追加する。Gatewayごとのfoundation state、transport schema、bridge delegate enumを準備する。`make`のtargetで対象Gateway/stageを必須にする。PRのstatus checkとして`make validate`と`make test`を実行するGitHub Actionsを追加する。
- **受入条件**:
  - `make validate`が、両foundation stateとcompose/schemaを検証して成功する。Gateway別のtransport/bridgeロード必須・禁止、bootstrap配置、third-party global entity1件と固定identity manifestを照合する（DP0 preflightの静的段階）。runtimeは仮設定で埋めない。
  - `make plan`の差分が、追加のcontrol plane、data plane certificate、local fileだけである。
  - `make deck-diff GATEWAY=api STAGE=foundation`と`make deck-diff GATEWAY=third-party STAGE=foundation`が別CPを対象にし、API既存v1 entityのupdate/delete=0、範囲外変更=0。schemaは両方の内容hashまで確認する。前提未承認ならlive not_run、完全受入保留。
  - API foundationはCertificate 2件だけを管理し、既存CA333のID・タグ・公開DER一致をdecK起動前にread-only検証する。共有CAのcreate/retag/update/deleteを行わず、欠落・不一致は停止する（WP1-CA-REUSE）。
  - 新しい秘密鍵、certificate、state、tokenがGitに入っていない（`.gitignore`と`git status`で確認）。
  - PRに、Actionsのstatus checkが表示される。
- **conformance**: —（基盤）

### WP2: Keycloak clientの置き換えとintrospectionの事前確認

- **範囲**: `third-party-fapi-mtls`、`third-party-fapi-pkj-mtls`、`api-gateway-introspection`の各clientを定義する。両Routeのaccess tokenへaudience `fapi-demo-api`と`api-gateway-introspection`を設定し、`azp`、redirect URI、refresh token rotationの切り替えを用意する。Keycloakのintrospection audience checkは無効化しない。
- **受入条件**:
  - **事前確認（最初に実施し、結果をIssueへ報告する）**: 両Routeの有効なcertificate-bound access tokenを専用clientでintrospectionし、`active: true`、一致する`cnf.x5t#S256`、両audience、`scope`、namespaced claimを確認する（RS-INT-AUD-02）。必須項目が欠ける場合は、WP3へ進まずDesign ownerへ戻し、P0のtoken有効性とPoPを維持する再設計を合意し、本来のFAPI要件への差分を記録する（ADR 0010/0011）。
  - `fapi-demo-api`はあるが`api-gateway-introspection`を含まないtokenでは、同じ専用clientによる応答が`active: false`になる（RS-INT-AUD-01）。他の不正要因での拒否と混同しないfixtureを使う。
  - 3つのclientが、宣言的なrealm定義から作られる。
  - 3rd Party clientのFAPI policy、PAR、PKCE S256、code lifetime 60秒以下が強制される。
  - A-CERT-01、A-CERT-02、B-AUD-01、B-JTI-01、B-CERT-01が、新しいclient IDで再現する。
- **conformance**: C-04、C-05、C-08、C-12〜C-14、C-18、R-02の前提

### WP3: API GatewayのResource Server化

- **範囲**: `kong/api-gateway.yaml`を作る。`tls-handshake-modifier`、OpenID Connect plugin（introspection、header only、PoP strict、audience、scope）、claim由来header、`tls-metadata-headers`、資格情報の除去、upstream mTLS、TLS protocolとcipher suiteを設定する。
- **受入条件**:
  - 3.16.0.0の実runtimeで、`tls-handshake-modifier`、`tls-metadata-headers`、`proof_of_possession_mtls`、`bearer_token_param_type`、introspectionのcache設定がschemaにあり、ADR 0010と同じpriorityで動くことを確認し、証跡をPRに添付する。
  - POP-01、POP-02、POP-03、RS-QUERY-01、RS-AUD-01、RS-SCOPE-01、ERR-01、HEADER-CERT-01、TLS-RS-01、RS-VALID-01が通る。tokenは、curlとtest用certificateで取得してよい。
  - introspectionのcache無効を既定とし、active検査を確認する。RS-REVOKE-01は追加説明用の任意テスト。実施時だけ前後のactive/API応答とcache条件を記録する。個別失効保証・反映SLAを本WPの必須受入にしない。
  - `deck diff`の結果が、意図したtag付きentityだけである。sync後はdiffが無い。
  - API runtime stateはfoundation全entityを同一ID/タグで含め、既存CA333を`[fapi2-demo]`のまま保持する。CAを除くv1 entityの除去、入口停止と復旧はWP3-MIGRATIONとして別preview/承認で扱う。
- **conformance**: R-01〜R-06

### WP4: Upstream API（PoP verifier）の変更

- **範囲**: API Gateway upstream certだけを受け付ける。転送された`X-Client-Cert`と`cnf`を照合する。`azp`からRouteを導出する。audienceを`fapi-demo-api`へ変える。evidenceの項目を追加する。
- **受入条件**:
  - unit testで次を確認する: 不正なpeer certificate、`X-Client-Cert`の欠落、thumbprintの不一致、`aud`の不一致、PS256以外のalgorithm、`azp`からのRoute導出。
  - UPSTREAM-01が通る。
  - responseに、raw token、cookie、private key、完全なcertificate、client assertionが含まれない（LEAK-01の一部）。
- **conformance**: R-06、本デモ固有の多層防御

### WP5: 3rd Party Gatewayへの移設とAS mTLS補完（P0/P1）

- **範囲**: `kong/third-party-gateway.yaml`を作る。v1のRoute A/BのOpenID Connect設定を移し、DP0/ADR 0012の`fapi-as-mtls-transport` global pluginとbridgeの`transport_delegate`を実装する。bootstrap origin、Route UUID/identity registry、専用metadata certを配置する。ServiceをAPI Gatewayへ向け、Route別のclient certificateを設定する。client供給headerを除去する。iss欠落guard/開始CSRF追加防御は本WPに含めない。
- **受入条件**:
  - **本体実装前のspike**: AS-MTLS-OBS-01を通す。test-only Keycloak observerのbuild/hook/peer chain/相関/negative TLSとstock PAR/revoke claimを確認。不成立ならneeds-design。計測imageは通常デモへ入れない。stock生成はpeer証跡契約の隔離OIDC fixture/公開endpoint設定で起動し、session作成後のstock logoutで各revokeを採取。harness relayのpeerを実AS証跡に代用せず、実Keycloak observerへjoinする。
  - **入口公開前のpreflight**: WP1の静的照合と設定反映後の全worker loaded/wrapper/registry ready観測がpassするまで、通常3rd Party入口/UIを開かない。transportだけ/両plugin欠落でfailし、入口閉鎖・Route A metadata未送信をAS-TRANSPORT-LIFECYCLE-01で確認。hybrid DPは閉鎖状態でCP設定を受領してよい。restart/設定変更時は再照合する。具体make/compose方式はWorkerが実装し、警告logだけのgateにはしない。
  - **WP5-BOOTSTRAP**: UI停止だけを遮断とみなさず、全worker ready前はASのpublic/internal originへのstock metadata/background通信も遮断する。CP設定受領は許可する。通常入口・AS通信の開放と再閉鎖を実証し、不成立ならneeds-design。runtime stateにfoundation全entityと固定UUIDの実Routeを包含する。
  - A-PAR-01、B-PAR-01、B-PKJ-01、PAR-01、PAR-02、PKCE-01、A-CNF-01、B-CNF-01、HDR-01、TLS-01が通る。
  - stockのISS-01（提示されたissの不一致拒否）が通る。ISS-02は将来シナリオとして未対応を開示する。
  - META-01、META-02を自動テストで確認する。
  - RT-01、RT-ROT-01が通る。
  - B-SPOOF-01、B-AUD-02、REDIR-01が通る。
  - B-TRANSPORT-01が通る。PAR/token/refresh/revokeのすべてでRoute B TLS certを提示・検証し、PKJWTでclient認証する。DP0成果にある補完契約と一致する。
  - AS-META-MTLS-01が両Routeで通る。cold cacheのdiscovery/JWKSとbridgeの独自discoveryを含め、certが実際に提示・検証される。共有cacheのcert選択はDP0の決定と一致する。
  - stock logout/revoke設定を明示する。revoke requestもmTLSとする。HTTP 200だけでは個別access token失効を証明しない点を手順に記録する。専用の失効順序制御は作らない。revoke失敗でもcertなし再送せず、stockが中断する場合は対象demo user限定の手動resetを使い、revoke結果とreset結果を別記録にする。
  - 既存bridgeのunit/drift検出テストを維持し、DP0で追加した送信経路のunit/integration回帰テストを通す。token/refreshは送信境界でbridge signerを呼び、PAR/revokeはstock PKJWTを維持する。自動POST再送・redirectは拒否し、設定/鍵変更はrestartで反映する。AS-TRANSPORT-GUARD-01/AS-TRANSPORT-LIFECYCLE-01をexact runtimeで通す（fresh assertionの同一POST拒否・2種類revoke許可、Gateway別実ロード/未ロード時guardを含む）。assertionは実際のoperationごとに生成し、静的assertionや秘密鍵をstateへ埋め込まない。
- **conformance**: C-01〜C-18のP0/P1対象（C-11とC-15の欠落guardは除外）

### WP6: UI、E2E、negative testの自動化と証跡

- **範囲**: UIの表示項目を新しい構成に合わせる。browser E2Eとnegative testを自動化する。logoutとRoute切り替えを確認する。証跡を自動で生成する。
- **受入条件**:
  - A-E2E-01、B-E2E-01、CLAIM-01、LOGOUT-A-01、LOGOUT-B-01、SWITCH-01、HEADER-01、LEAK-01、ALG-01が自動化で通るか、文書化されたbrowser evidence手順を持つ。
  - RESET-01が両Routeから通る。Route cookie/SSOをresetして、別Route・別userで新しい認可フローと期待するclaimを確認する。手動resetを使う場合は対象demo userに限定した手順をREADMEへ記録する。
  - LOGOUT-A/B-01とSWITCH-01はRESET-01の条件で判定する。REVOKE-RS-01の厳密な失効証跡は任意。リセット結果からtoken失効を保証しない。
  - CSRF-01/ISS-02/DPoPは今回未対応と記録する。標準機能・custom補完・未検証を分けた[お客様向け説明](third-party-demo-explainer.md)を実装証跡で更新する。
  - clean checkoutから、2つのcontrol plane、2つのdata plane、Keycloak、Upstream APIを起動して両Routeを実行する手順がREADMEにあり、実際に再現できる。
- **conformance**: P0/P1対象の証跡とF/N/Aの理由をまとめる。全FAPI行の合格は要求しない

## 検証方法

### 証跡の形式

- 各シナリオは、検証IDをキーにした証跡を持つ。自動テストは、`.generated/evidence/<scenario-id>.json`（Git管理外）へ結果を出力する。
- PRには、検証ID、結果、証跡の要約（HTTP status、thumbprintの先頭12文字、`azp`、`alg`など）を表で添付する。token、cookie、assertion、private key、authorization code、完全なcertificateは載せない。
- ASのTLS peer証跡は[test-only Keycloak observer](third-party-as-peer-evidence.md)から取得し、Gatewayの相関ID付きoperation結果へjoinする。Gateway option logだけでmTLS成功としない。その他の通信レベル証跡（certificateの一貫性、PAR、header）はGatewayまたはtest harnessで取得する。tcpdumpなど、手作業の取得に依存しない。

### PRの必須記載事項

1. `Refs #<issue>`
2. 受入条件の対応表（受入条件 → 実装箇所 → 検証ID → 結果）
3. conformance文書の該当行、このPRのP0/P1/D受入とF/N/Aの除外理由。未実施をpassにしない
4. `make validate`、`make test`、該当するdecK diffの結果
5. 設計からの逸脱とその理由（SHOULDからの逸脱を含む）
6. 未完了の受入条件と、その理由

### Reviewerのchecklist

- 受入条件が、すべて証跡で裏付けられているか（「動いた」という記述だけのものが無いか）
- P0のfail closed（certificate、鍵、issuer、token有効性/PoP）を維持しているか。iss欠落は将来対応として開示され、提示されたissの不一致検査は残っているか
- client供給の`X-Client-Cert*`、`X-Demo-*`、`X-Fapi-*`、`client_assertion*`が、境界で除去または上書きされているか
- 秘密情報が、Git、decK state、Terraform output、log、responseに無いか
- 設計（要件書、ADR 0009〜0012、DP0補完契約）からの無申告の逸脱が無いか
- 3.16.0.0固有の挙動に依存する箇所に、回帰テストまたは確認手順があるか

### Design ownerの独立検証

merge後、Design ownerはmain上で次を確認してから、Technical Completion Reportを記録する。

- WPごとの主要シナリオを、PR作成者とは独立に再実行する（少なくとも、positiveとnegativeを各1件）。
- conformance文書の該当行について、証跡が要件を満たすことを確認する。
- 既知のgap、DPoP追加候補、resetと失効保証の区別、AS requestモードの制約、ADR 0010の再設計があればその影響を記録する。P0失敗や未検証を完了扱いにしない。一方、F項目の未対応だけを理由に必須デモの完了を止めない。

## シナリオの優先度と除外

- **P0**: A/B-E2E-01、A/B-CNF-01、A-CERT-01/02、B-PKJ-01、B-AUD-01/02、B-JTI-01、B-CERT-01、B-SPOOF-01、B-TRANSPORT-01、AS-MTLS-OBS-01、AS-META-MTLS-01、AS-TRANSPORT-GUARD-01、AS-TRANSPORT-LIFECYCLE-01、POP-01〜03、TLS-01、LEAK-01。PKJWTの署名不正・期限切れ・jti再送fixtureはDP0契約のB-AUD-01/B-JTI-01で固定した。
- **P1**: A/B-PAR-01、PAR-01/02、PKCE-01、META-01/02、RT-01、RT-ROT-01、RS-VALID-01、RS-INT-AUD-01/02、RS-QUERY-01、RS-AUD-01、RS-SCOPE-01、ERR-01、HDR-01、HEADER-01、HEADER-CERT-01、UPSTREAM-01、CLAIM-01、ISS-01、REDIR-01、ALG-01、TLS-02、TLS-RS-01。新規customが必要ならDesign ownerへ戻す。
- **D**: RESET-01、LOGOUT-A/B-01、SWITCH-01（新reset契約で判定）。
- **F/任意**: ISS-02、CSRF-01、RS-REVOKE-01、REVOKE-RS-01、DPoP。専用の厳密な失効テストを作ることは今回の受入条件ではない。
