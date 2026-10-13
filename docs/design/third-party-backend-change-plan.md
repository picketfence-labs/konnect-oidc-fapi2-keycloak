# 3rd Partyバックエンド分離の影響と対応計画

- 状態: 図・文書はPR #30でmainへ先行反映済み。コードは別Draft PR #31。承認済み残6操作のTP復旧同期が成功・実差分0。隔離IdPの限定更新の比較で停止し、原値を確認中。新経路の実行受入は未完了
- 日付: 2026-10-13
- 基準: main `933a51a`（文書整備PR #29をmerge済み）
- 役割: Coordinatorが全体条件と図・文書を統括。コード側はManagerがWorkerへ委譲し、成果を検証・統合する

## 今回の前提

UIを提供する役割と、API提供者への業務API呼出しを分離する。ブラウザーは3rd Partyのサービスへ要求し、3rd PartyバックエンドがAPI提供者側のKongへアクセスする。バックエンドの外向き通信を、再び3rd Party Kongへ戻す必要はない。この点は利用者確認済み。

```text
UI取得:    ブラウザー → 3rd Party Kong → 静的UIサービス
業務要求:  ブラウザー → 3rd Party Kong → 3rd Partyバックエンド
外部API:   3rd Partyバックエンド → API提供者側Kong → Resource Server
認証:      ブラウザー ↔ Keycloak、3rd Party Kong ↔ Keycloak
```

承認済み計画に従い、UI取得もKongを共通入口とする。静的ファイル配信とバックエンドは別プロセスのままにする。ブラウザーからAPI提供者側KongやResource Serverを直接呼ぶ経路、バックエンドの公開ポートは設けない。

## 調査時点（933a51a）の構成との差分

現行の3rd Party KongはOAuthクライアントであり、認可コード・PAR・PKCE・セッション・refresh等を扱い、API側Kongを直接upstreamとしている。独立した3rd Partyバックエンドがない。UIサービスはnginxによる静的配信である。

「ブラウザーがAPI提供者の公開URLへ直接アクセスする」ことと、「3rd Partyに業務処理用バックエンドが存在しない」ことは区別する。必要な変更は後者の解消と、ブラウザーからの入口の整理であり、図の矢印の修正だけでは完了しない。

| 項目 | 現行 | 変更案 |
|---|---|---|
| UI配信 | 静的nginxを独立公開 | TP Kongから静的UIへ転送 |
| 利用者の業務要求 | TP KongがそのままAPI側Kongへ転送 | TP Kongが認証後にTPバックエンドへ転送 |
| 外部APIを呼ぶ主体 | TP Kong | TPバックエンド |
| OAuthクライアント・セッション | TP Kong | TP Kongを維持 |
| APIへのBearer token | KongからAPI側へ | Kongから内部バックエンドへ、バックエンドからAPI側へ |
| APIに提示する証明書 | KongのRoute A/B証明書 | バックエンドから同じRoute A/B証明書を提示 |
| API側Kong・Resource Server | introspection・PoP・JWT再検証 | 検証方針を維持し、新経路で再確認 |

ソースで確認した現行経路は次のとおり。ブラウザーは現在もAPI提供者側Kongを直接呼んでいない。

```text
UI:   ブラウザー → localhost:3443 → 静的nginx
API:  ブラウザー → localhost:8443 → TCP forward → TP Kong
                  → kong-api:8443/fapi-api/evidence → pop-verifier:9443/evidence
```

## 推奨方式と信頼境界

既存デモのKongによるFAPIクライアント認証を維持し、薄い3rd Partyバックエンドを追加する。OAuthクライアントをバックエンドへ移す方式は、認可開始・callback・セッション・refresh・PKJWTをアプリ側へ再実装することになり、今回の最小変更案には採らない。

- Kongが利用者ごとのOAuthセッションを管理し、取得したアクセストークンを内部通信だけでバックエンドへ渡す。ブラウザーへtokenを返さない。client credentialsへの置換は行わない。
- バックエンドはRoute A/Bごとの固定内部エンドポイントを持ち、固定されたAPI側Kongへだけ送信する。呼出し元が指定したURL・証明書パス・認証方式を採用しない。
- Kong→バックエンドは専用identityのmTLSとし、そのKongからの要求だけを受け付ける。ブラウザー由来のAuthorizationや内部用ヘッダーを、認証済み要求として信頼しない。
- バックエンド→API側KongはBearer tokenとRoute A/B証明書によるmTLSを使う。tokenの`cnf.x5t#S256`に束縛された証明書と、API接続時の証明書を一致させる。
- そのため、Route A/BのTLS秘密鍵を同じ3rd Party信頼領域内のKongとバックエンドで共有する。読み取り専用の限定mountとし、PKJWT署名鍵・refresh token・セッションCookieはバックエンドへ渡さない。これは鍵の保持箇所が増える設計上のトレードオフである。
- Kong→バックエンド用証明書と、AS認証・token束縛用のRoute証明書は別にする。ServiceのTLS証明書変更がAS送信identityへ影響しないことをコードと試験で確認する。
- `tls_client_auth_cert_id`、transportのRoute別manifest、bridgeのRoute B identityはOAuth用のまま維持する。現在の「Service証明書=OAuth証明書」というvalidatorの固定条件は、新しい内部hopとの分離に合わせて更新する。stock実装を含む実際のAS送信証明書は、結合時の観測で確認する。
- バックエンドはAPI応答から表示を許可した検証結果だけを返す。token、Cookie、assertion、秘密鍵、完全な証明書をログ・エラー・UIへ出さない。

### 実装へ渡す接続契約

| 接続・処理 | 契約 |
|---|---|
| ブラウザーの共通入口 | `https://localhost:8443`。既存のreadinessで制御するTCP forwardを維持 |
| 静的UI | TP Kong → `http://ui:80`（内部ネットワークのみ）。nginxの既存HTTPSリダイレクトを静的配信へ変更し、Cookie/Authorizationを転送しない |
| 公開A/Bとcallback | `/api/fapi/mtls`、`/api/fapi/pkj-mtls`を維持。login/logoutの戻り先は共通入口へ合わせる |
| バックエンドA | `https://third-party-backend:9444/evidence/route-a`。専用Kong identityのmTLS要求だけを受理 |
| バックエンドB | `https://third-party-backend:9444/evidence/route-b`。同上。A/B選択は固定内部pathで行い、caller headerから選ばない |
| 外部API | 固定`GET https://kong-api:8443/fapi-api/evidence`。SNI/CA検証、A/B証明書、timeout/応答サイズ上限。任意URL・redirect追従・自動retryは設けない |
| health | 内部`/healthz`の認証済みprobeまたはcontainer-local probe。構成・鍵読込のreadyを確認し、利用者tokenや外部APIは使わない |
| 結果 | 既存の成功応答schemaを維持した許可項目のみ、`Cache-Control: no-store`。upstreamのraw header/errorは返さない |

静的UIまで内部HTTPSとする場合は、現行UI証明書にない`DNS:ui`のSANが必要になる。静的配信の内部HTTP案を採る場合も、バックエンド・AS・APIのmTLSは維持する。静的root/asset RouteはOAuth A/Bのplugin scopeと分け、API pathの誤りをSPA fallbackで正常表示しない。

## 並行作業の進め方

最初にManagerとCoordinatorが、公開入口・内部エンドポイント・認証担当・token/証明書の受渡し・応答の許可項目を同じ契約として固定する。その後、コードと図・文書を並行して進める。資料提供をバックエンドの実行受入完了まで待たせない。

| 段階 | 担当 | 成果・依存 | 完了条件 |
|---|---|---|---|
| 1. 契約固定 | Coordinator + コードManager | 要件差分、ADR、API経路、identity、受入項目 | 認証・通信・鍵の担当に矛盾がない |
| 2A. 図・文書の先行提供 | Coordinator配下の図・文書担当 | 全体構成を先に、続いてRoute A/BとARCHITECTURE/README。段階1だけに依存 | 変更予定を明示した図と説明を閲覧できる |
| 2B. バックエンド | Manager → Worker | 専用mTLS入口、A/B固定API呼出し、応答整形、漏洩防止 | 正常・拒否の単体/fixture検証とManager review |
| 2C. 経路・起動統合 | Manager → Worker | Gateway、PKI、Compose/native override、UI入口、readiness、生成/検証script | 起動前guardを維持し、設定と実装の契約が一致 |
| 3. 結合・受入 | コードManager、Coordinatorが全体条件を照合 | 新経路でA/B、refresh、logout、負例。必要な適用は具体的なpreview後に扱う | 新経路の証跡と資料が一致 |
| 4. 資料の先行PRとコード受入 | Coordinator + Manager | 図・文書だけを先にmainへ提案。コードは別ブランチ・別PRで受入結果を添える | 資料完成を利用者へ通知し、未実装を実装済みと表示せずreview可能 |

図・文書の先行版は「承認済み設計・実装／受入前」と表示する。現在の受入済みPagesを無告知で上書きせず、必要なら別URLで変更案を提供する。受入後に正式版のリンクと公開内容をそろえる。旧receiptを新経路の成功証跡として再利用しない。

同時に進める担当はCoordinator、コードManager、コードWorker、図・文書Workerの4枠を基本とする。コードWorkerはバックエンド本体から設定統合へ順に進み、図・文書Workerとは変更ファイルを分ける。UIのJavaScript/nginx設定もコードManager側が所有する。別のコードWorkerが必要になった場合は、空いた枠で交代・分担する。

## 図・文書担当への変更契約

- 全体図: 3rd Partyの境界内に、Kong、静的UIサービス、業務バックエンドを別々の構成要素として描く。外部API呼出しの矢印はバックエンドからAPI側Kongへ向ける。利用者の要求は3rd Party Kongを通す。
- Route A/B: 同じ3rd Partyスイムレーン内でKongとサービスを区別する。Kongの認証・token取得の後に、バックエンドへの内部要求とバックエンドによる外部API呼出しを追加する。
- UI配信、利用者認証、業務要求、外部API通信を別の経路として表す。応答もバックエンド・Kongを通ってブラウザーへ戻す。
- A/Bの認証方式・証明書束縛は維持する。Kong→バックエンド用の専用identityとAPI向けRoute証明書を混同しない。
- `ARCHITECTURE.md`の責任分担、通常フロー、Route詳細、証明書表、FAPI対応・差分を更新する。README、要件、foundation/transport契約、受入表、引き継ぎの現行説明も追随させる。
- ArchifyのJSON・HTML・PNG、9/9検査、4画面サイズのブラウザー確認、明暗画像レビュー、公開HTMLのhash一致を新版として記録する。

## コード側の主な影響範囲

| 分野 | 対象 | 変更・確認内容 |
|---|---|---|
| Gateway経路 | `kong/third-party-gateway.yaml` | A/Bのupstreamをバックエンドへ変更。静的UIのService/Routeを追加。AS用identityと内部hop identityを分離 |
| 新バックエンド | 新しい専用ディレクトリとテスト | 固定API接続、専用mTLS入口、A/B証明書選択、応答整形、エラー・漏洩対策 |
| PKI・secret生成 | `scripts/generate-pki.py`、`generate-dev-assets.sh`、`render-runtime-secrets.py` | バックエンドserverと内部hopのidentity、必要な鍵だけのmount。既存Route鍵の利用範囲を明示 |
| 起動・再現 | `docker-compose.yml`、`docker-compose.demo-native.yml`、`scripts/require-wp5-readiness.sh` | 新サービスと依存、非公開ネットワーク、image/native再現、ready判定、失敗時停止の対象追加 |
| 宣言・変更guard | `scripts/wp1_target.py`、`scripts/run-deck.py` | 既存のService数・API直結先・証明書一致・11件追加のみという旧変更条件を、今回の契約とpreviewに合わせる。新しい内部hop用Certificate entityを追加し、A/B entityを置換しない。foundation/runtimeの許可entity集合も明示更新 |
| ブラウザー入口 | `ui/index.html`、`ui/default.conf`、Keycloakのredirect設定 | Kong共通入口と相対URL、login/logout terminal、静的配信内部化。callback・client IDは不要に変えない |
| 回帰検証 | static/WP1/WP5/runtime/PKI/UIの各test、stock_flow/fixture、Makefile | 固定port/Service数/直接upstreamの前提更新。新経路のbackend到達と拒否・秘密非露出の試験追加 |

`scripts/wp5-demo-forward.py`のTCP転送は、Kongを共通入口として維持するなら基本的に再利用できる。API側Kong・Resource Serverの検証処理は今回の変更主体ではない。

## 受入で確認すること

1. UIと業務要求は3rd Party Kongを通り、業務APIはバックエンドからAPI側Kongへ到達する。ブラウザーのnetwork記録とサーバー側の安全な観測を突き合わせる。
2. A/Bとも利用者ごとのログイン、API200、claim/header、JWT署名、証明書束縛、refresh、logoutが新経路で成立する。
3. 無認証、Kongを迂回したバックエンド呼出し、内部ヘッダー偽装、A/B証明書取り違え、任意URL指定を拒否する。
4. ASには従来どおりのRoute証明書が提示され、API呼出しにはそれと同一の証明書が使われる。内部hopの専用証明書への誤束縛が起きない。
5. Cookieや内部assertionを外部APIへ転送しない。token/鍵等をUI・応答・ログへ露出しない。
6. worker readiness、起動・停止/再起動、Compose/native override、clean checkout再現と検証scriptを新サービス込みで確認する。

同時A/B要求でtoken・証明書が交差しないこと、バックエンド停止時に入口が閉鎖されることも確認する。バックエンドで偽装ヘッダーを除去しただけでAPI側の偽装拒否が実行されたとは扱わず、API側単体の負例と新経路の負例を分けて残す。

既存のAPI側PoP/JWT検証やAS単体の証跡は元の条件の履歴として維持する。通常A/B、経路、UI入口、readiness、再現性の旧結果は新構成の受入を代替しない。既知のPAR `client_id`、revocation metadata、`iss`欠落、開始CSRF等は今回の構成変更と混ぜて完全適合扱いにしない。

## 進行・負担・操作境界

図・文書は実行環境を待たず先行できる。一方、コードはバックエンド追加だけでなく、mTLS identity、生成物、guard、既存harnessまで横断するため、結合・回帰確認を独立工程として扱う。所要時間と費用は未計測であり、固定値を置かない。

現在の影響調査はCoordinator／Manager／source trace Workerを分離し、ManagerとWorkerにはSol 6.1／Highを指定した。実装時もManagerが契約・分担・検証を管理する。認証・信頼境界を跨ぐ初期統合はSol 6.1／Highを推奨し、仕様と試験が閉じた局所実装だけを現行routingに従って別Workerへ渡す。

2026-10-13に利用者が計画の続行を承認した。図・文書は`docs/third-party-backend-architecture`で先行し、完成時に通知してmainへのPRを優先する。コードは別worktreeの`feat/third-party-backend`でManager/Workerが変更する。Docker実行・CP適用・新image build/publishは具体的なpreviewを提示し、人による確認後に扱う。PR #29はmerge済みであり、既存受入と旧receiptは履歴として維持する。

## 実装・プレビューの到達点（2026-10-13）

最新: 利用者が下記の残6操作を承認し、新票・Routes validation・fresh diff・late rereadを経てTP同期1回が成功、postdiff0を確認しました。Python/UI imageをdigest固定して隔離first4を起動、Keycloak/TP worker readinessが成功。その後IdPのA postlogout更新の非対象field比較で停止しました。元DBを開かずコピーのoffline readで原値を確認中です。B更新・Backend/UI起動・新経路の受入は未実施。以下は復旧前までの経緯であり、最新の操作状態は[準備・適用・受入手順](third-party-backend-runtime.md)を参照してください。

バックエンド、専用hop、Gateway/UI/PKI/role、readiness、今回専用schema2 guardを実装。Manager独立でmake validate、380 unittest、UI/Lua、native Compose設定が成功しました。利用者の具体プレビュー一括承認後、fresh4create/6update/0deleteと承認票の一致を確認してTP同期を開始しましたが、CLI nonzeroで停止しました。read-only現状ではhop Certificate/UI Serviceの作成とA/B Service更新の4操作が反映済み。残りはUI Route/UI transformerの2create、A/B CORS/OIDCの4updateです。削除と予期しない対象変更はありません。

CLIの`--silence-events`修正はJSONも抑止するため撤回。その後の移行案内除去adapterも、旧`~^/`形式を有効とした誤判断を訂正して撤回します。正規の非作成Routes validationで旧RouteのHTTP400と新native expression案の受理を確認しました。初回同期のraw失敗理由は保持しておらず、旧Routeだけが原因とは断定しません。3パス完全一致のnative expression、固定6操作の`migration-recovery`、同期前のRoutes validationを実装し、Managerが独立確認します。元4/6承認票を流用せず、修正済みソースのfresh残差分を人がレビューするまで再同期しません。

旧DB・素材を変えない隔離候補の6サービス設定とDB snapshot一致を確認済み。CPは共有されるため、適用は既存TP CPへ接続するDPに反映されます。Docker/image取得・IdP更新は未実施で、A/B post-logout属性のlive値は未照合です。[準備・適用・受入手順](third-party-backend-runtime.md)を参照してください。復旧対象の再確認後は、既に承認された隔離受入範囲に従います。新経路の受入は全項目not_runのままです。

## 調査根拠（933a51a時点）

コード側ManagerがWorkerのsource traceを原文と照合してreviewし、AS/Serviceの証明書選択を追加調査した。Coordinatorは目標経路、責任分担、図との対応、並行作業の依存と未実施範囲を確認し、本計画へ統合した。ここでの調査はソースによる確認であり、現在稼働中の環境の観測ではない。Managerの詳細報告はGit外の`.generated/evidence/tp-backend-plan-20261013/manager-impact.md`へ保存した。

- [UI](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/ui/index.html): 48/54行の認可開始、88～90行のA/B宛先、137～142行のCookie付きfetchはTP Kong向け
- [nginx設定](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/ui/default.conf): 21～25行は静的配信。API proxyはない
- [3rd Party Gateway設定](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/kong/third-party-gateway.yaml): 50～59行と138～146行はAPI側への直接upstream。OIDCの証明書IDは96/210行
- [Compose](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/docker-compose.yml): 5サービス構成でバックエンドなし。145～155行にTP Kongの鍵mount
- [構成validator](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/scripts/wp1_target.py): 299～301行のentity集合、314～345行のService数・直結先・証明書一致条件
- [readiness supervisor](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/scripts/require-wp5-readiness.sh): 既存worker gateとUI/TP lifecycle。新バックエンドの管理は未実装
- [調査時点の全体構成図ソース](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/docs/design/workflows/third-party-architecture.architecture.json): バックエンド追加前。サービスを静的UIと表し、KongがAPIを呼ぶ構成
- [調査時点のRoute A図ソース](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/docs/design/workflows/route-a-mtls.workflow.json) / [Route B図ソース](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/blob/933a51a/docs/design/workflows/route-b-pkj-mtls.workflow.json)
