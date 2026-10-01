# 3rd Party経由FAPI 2.0デモ Delivery plan

## この文書の目的

[3rd Party経由FAPI 2.0デモ要件](third-party-fapi2-requirements.md)を実装するための、作業分割、役割分担、検証方法を定義する。各Work package（WP）は、GitHub Issueとして起票する作業契約の原案である。

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

1. Design ownerが設計PRを作成し、利用者がarchitectureをレビューしてmergeする。
2. Design ownerが、Epic Issueと各WPのIssueを起票し、`ready-for-development`にする。
3. WorkerがIssueを1つ取り、`feat/<wp>-<slug>` branchで実装し、`Refs #<issue>`付きのPRを作る。PRはIssueを自動closeしない。
4. ReviewerがPRをレビューし、PR commentに判定（approve / request changes）と指摘を残す。
5. 利用者がPRをmergeする。
6. Design ownerがmain上で独立検証を行い、IssueへTechnical Completion Report（成果、証跡、依頼元の確認手順、制約と残リスク）を記録する。
7. 利用者が受入結果を記録し、Issueをcloseする。不合格なら`status:needs-fix`へ戻す。

## Work packages

依存関係: WP1 → WP2 → WP3 → WP5 → WP6。WP4はWP1の後、WP3と並行して進められる。

### WP1: 2つのGatewayの基盤

- **範囲**: Terraformで3rd Party用のKonnect control planeとdata plane certificateを追加する。composeを`kong-api`と`kong-third-party`へ分ける。開発PKIに新しい鍵材料（API Gateway server TLS、introspection client、upstream client）を追加する。decK stateをGatewayごとに分ける。`make`のtargetで対象Gatewayを指定できるようにする。PRのstatus checkとして`make validate`と`make test`を実行するGitHub Actionsを追加する。
- **受入条件**:
  - `make validate`が、両方のdecK stateとcompose構成を検証して成功する。
  - `make plan`の差分が、追加のcontrol plane、data plane certificate、local fileだけである。
  - `make deck-diff GATEWAY=api`と`make deck-diff GATEWAY=third-party`が、それぞれ別のcontrol planeを対象にする。
  - 新しい秘密鍵、certificate、state、tokenがGitに入っていない（`.gitignore`と`git status`で確認）。
  - PRに、Actionsのstatus checkが表示される。
- **conformance**: —（基盤）

### WP2: Keycloak clientの置き換えとintrospectionの事前確認

- **範囲**: `third-party-fapi-mtls`、`third-party-fapi-pkj-mtls`、`api-gateway-introspection`の各clientを定義する。audience `fapi-demo-api`、`azp`、redirect URIを設定する。refresh token rotationの切り替えを用意する。
- **受入条件**:
  - **事前確認（最初に実施し、結果をIssueへ報告する）**: certificate-bound access tokenを`api-gateway-introspection`でintrospectionした応答に、`active`、`cnf.x5t#S256`、`aud`、`scope`、namespaced claimが含まれるか。含まれない場合は、ADR 0010のFallbackのどちらを採るかをDesign ownerと決めてから、WP3へ進む。
  - 3つのclientが、宣言的なrealm定義から作られる。
  - 3rd Party clientのFAPI policy、PAR、PKCE S256、code lifetime 60秒以下が強制される。
  - A-CERT-01、A-CERT-02、B-AUD-01、B-JTI-01、B-CERT-01が、新しいclient IDで再現する。
- **conformance**: C-04、C-05、C-08、C-12〜C-14、C-18、R-02の前提

### WP3: API GatewayのResource Server化

- **範囲**: `kong/api-gateway.yaml`を作る。`tls-handshake-modifier`、OpenID Connect plugin（introspection、header only、PoP strict、audience、scope）、claim由来header、`tls-metadata-headers`、資格情報の除去、upstream mTLS、TLS protocolとcipher suiteを設定する。
- **受入条件**:
  - 3.16.0.0の実runtimeで、`tls-handshake-modifier`、`tls-metadata-headers`、`proof_of_possession_mtls`、`bearer_token_param_type`、introspectionのcache設定がschemaにあり、ADR 0010と同じpriorityで動くことを確認し、証跡をPRに添付する。
  - POP-01、POP-02、POP-03、RS-QUERY-01、RS-AUD-01、RS-SCOPE-01、ERR-01、HEADER-CERT-01、TLS-RS-01、RS-VALID-01が通る。tokenは、curlとtest用certificateで取得してよい。
  - REVOKE-RS-01（Keycloakでaccess tokenをrevokeした後の拒否）が、cacheのTTL以内に通る。
  - `deck diff`の結果が、意図したtag付きentityだけである。sync後はdiffが無い。
- **conformance**: R-01〜R-06

### WP4: Upstream API（PoP verifier）の変更

- **範囲**: API Gateway upstream certだけを受け付ける。転送された`X-Client-Cert`と`cnf`を照合する。`azp`からRouteを導出する。audienceを`fapi-demo-api`へ変える。evidenceの項目を追加する。
- **受入条件**:
  - unit testで次を確認する: 不正なpeer certificate、`X-Client-Cert`の欠落、thumbprintの不一致、`aud`の不一致、PS256以外のalgorithm、`azp`からのRoute導出。
  - UPSTREAM-01が通る。
  - responseに、raw token、cookie、private key、完全なcertificate、client assertionが含まれない（LEAK-01の一部）。
- **conformance**: R-06、本デモ固有の多層防御

### WP5: 3rd Party GatewayへのRoute A/Bの移設

- **範囲**: `kong/third-party-gateway.yaml`を作る。v1のRoute A/BのOpenID Connect設定と`fapi-client-auth-bridge`を移す。ServiceをAPI Gatewayへ向け、Route別のclient certificateを設定する。`iss`欠落のguardを実装する。client供給headerを除去する。
- **受入条件**:
  - A-PAR-01、B-PAR-01、B-PKJ-01、PAR-01、PAR-02、PKCE-01、A-CNF-01、B-CNF-01、HDR-01、TLS-01が通る。
  - ISS-01、ISS-02が通る。guardを`pre-function`で実装できなかった場合は、理由と代替実装をPRに記録する。
  - META-01、META-02を自動テストで確認する。
  - RT-01、RT-ROT-01が通る。
  - B-SPOOF-01、B-AUD-02、REDIR-01が通る。
  - `fapi-client-auth-bridge`のunit testと、内部moduleのdrift検出テストが、引き続き成功する。
- **conformance**: C-01〜C-17

### WP6: UI、E2E、negative testの自動化と証跡

- **範囲**: UIの表示項目を新しい構成に合わせる。browser E2Eとnegative testを自動化する。logoutとRoute切り替えを確認する。証跡を自動で生成する。
- **受入条件**:
  - A-E2E-01、B-E2E-01、CLAIM-01、LOGOUT-A-01、LOGOUT-B-01、SWITCH-01、HEADER-01、LEAK-01、ALG-01が自動化で通るか、文書化されたbrowser evidence手順を持つ。
  - logout後のREVOKE-RS-01（3rd Party Gatewayのlogoutでrevokeされたaccess tokenが、API Gatewayで拒否される）が通る。
  - CSRF-01の観察結果を、既知のgapとして記録する。
  - clean checkoutから、2つのcontrol plane、2つのdata plane、Keycloak、Upstream APIを起動して両Routeを実行する手順がREADMEにあり、実際に再現できる。
- **conformance**: 全行の証跡をまとめる

## 検証方法

### 証跡の形式

- 各シナリオは、検証IDをキーにした証跡を持つ。自動テストは、`.generated/evidence/<scenario-id>.json`（Git管理外）へ結果を出力する。
- PRには、検証ID、結果、証跡の要約（HTTP status、thumbprintの先頭12文字、`azp`、`alg`など）を表で添付する。token、cookie、assertion、private key、authorization code、完全なcertificateは載せない。
- 通信レベルの証跡（certificateの一貫性、PAR、header）は、Gatewayのログまたはtest harnessで取得する。tcpdumpなど、手作業の取得に依存しない。

### PRの必須記載事項

1. `Refs #<issue>`
2. 受入条件の対応表（受入条件 → 実装箇所 → 検証ID → 結果）
3. conformance文書の該当行のうち、このPRで充足する行
4. `make validate`、`make test`、該当するdecK diffの結果
5. 設計からの逸脱とその理由（SHOULDからの逸脱を含む）
6. 未完了の受入条件と、その理由

### Reviewerのchecklist

- 受入条件が、すべて証跡で裏付けられているか（「動いた」という記述だけのものが無いか）
- fail closedになっているか（certificate、鍵、issuer、`iss`が欠落したときに通過しないか）
- client供給の`X-Client-Cert*`、`X-Demo-*`、`X-Fapi-*`、`client_assertion*`が、境界で除去または上書きされているか
- 秘密情報が、Git、decK state、Terraform output、log、responseに無いか
- 設計（要件書、ADR 0009、ADR 0010）からの無申告の逸脱が無いか
- 3.16.0.0固有の挙動に依存する箇所に、回帰テストまたは確認手順があるか

### Design ownerの独立検証

merge後、Design ownerはmain上で次を確認してから、Technical Completion Reportを記録する。

- WPごとの主要シナリオを、PR作成者とは独立に再実行する（少なくとも、positiveとnegativeを各1件）。
- conformance文書の該当行について、証跡が要件を満たすことを確認する。
- 残リスクと既知のgap（CSRF-01、ADR 0010のFallbackを採った場合はその内容）を明記する。
