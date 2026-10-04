# ADR 0018: WP5の同一要求内ハンドラー再入を別test-only variantで観測する

- 状態: 設計採用、再入runtime sub-gate受入完了
- 日付: 2026-10-04
- 対象: WP5 5aのrepeated-handler実動作確認

## 背景

direct TLS v3は40/40 PASSで、AS側の証明書観測と後片付けを独立確認した。ただし、既存observerはrequest-local markerを検出すると記録せずreturnするため、observer行が1件であることだけではハンドラーが実際に複数回呼ばれたと証明できない。

固定版KeycloakのPAR経路は、[RealmsResource.getProtocol](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/RealmsResource.java)、[OIDCLoginProtocolService.resolveExtension](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolService.java)、[ParRootEndpoint.request](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/par/endpoints/ParRootEndpoint.java)のsub-resource locatorを経て`ParEndpoint.request`へ到達する。[KeycloakHandlerChainCustomizer](https://github.com/keycloak/keycloak/blob/26.7.4/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/KeycloakHandlerChainCustomizer.java)はendpoint invokerを`TransactionalSessionHandler`で包む。この経路を実動作試験の候補にするが、source確認だけで再入を受け入れない。

## 決定

受入済みv3のsource、image、receiptを保持し、別のtest-only variantを作る。生成時にv3 helperのdigestと固定anchorを検査し、request-localな再入診断だけを追加する。ADR 0017のpublished-JAR buildを使い、変更するclassは引き続きhandlerとhelperの2つに限定する。通常デモ、Gateway plugin、OAuth処理、TLS設定は変更しない。

独立flag `FAPI_DEMO_AS_PEER_REENTRY_PROBE=true`で診断を有効にする。observerのOFF guardは先頭に維持する。初回の固定inventory・method・厳密な相関IDの検証後、これらのsanitized値だけを同じ`RoutingContext`に保持する。markerを検出した後続呼出しは、別prefix `WP5_AS_PEER_REENTRY v=1`に相関ID・endpoint・method・path・呼出し回数を記録し、既存の早期returnを維持する。回数は2〜16に限定し、上限超過は固定errorとして受入を失敗させる。未知pathや不正IDは診断対象外とする。query、body、token、cookie、追加header、certificateは読み出さない。

canonical observerの13 field、PKIX検査、peer取得、通常HTTP結果を変えない。記録状態をworker/session/globalへ持ち出さない。新しい管理API、debug port、Java agentは追加しない。

## 受入と継続条件

実HTTPのPAR要求について、同じ相関IDの診断で2回以上の呼出しと連番を確認し、canonical observer行が厳密に1件であることを照合する。診断OFFでは診断行0件、observer OFFでは双方0件とし、ON/OFFのHTTP結果が一致することを確認する。parserは固定field・値・有限件数・対応付けを検証する。生成やmockの試験は実動作証明に数えない。

新しいimageと隔離runtimeの具体的previewをRootが確認してから実行する。利用者の継続実行指示の範囲で、通常環境や外部Control Planeへ作用しない所有fixtureを使う。範囲の拡張や契約不成立があれば判断を求める。stock PARの実署名・claimゲートが不成立なら、この追加imageのbuild/runtimeより先に原因を整理する。

v3 receiptを上書きせず、新しい入力manifest、image identity、runtime receipt、cleanup結果を別に残す。この診断の成功だけではstock PAR/logout revokeやWP5全体を完了扱いにしない。

runtimeの専用networkは[ADR 0019](0019-wp5-stock-claim-fixture-boundaries.md#隔離fixtureのnetwork2026-10-04追記)に従い、成功済みdirect TLS v3と同じbridgeを使う。r3の到達timeoutとcleanup記録は保持し、新しいr4 fixtureで再実行する。計測imageの変更や再buildは不要である。

## 実動作の受入（2026-10-04）

r4は3モードで同じHTTP401を維持し、canonical observer行は順に1/1/0件だった。計測ONの同一PAR相関IDに再入count2/3/4が連続して対応し、canonical行は1件だけである。両ONモードの13 fieldと専用Route B leafのPKIX・有効性・clientAuth EKUを照合した。OFFモードは両marker0件。完全なbounded log scanと専用project・volume・network・port・private fixtureの回収をRootが独立確認した。

terminal receiptは`/private/tmp/wp5-as-reentry-probe-run-receipt-20261004-v4-r4.json`、SHA-256は`0649988015f31ea238683540c8eab0be1991f8001a79a90ba3f73d6dc7e1b515`。Root証跡は`.generated/evidence/wp5-root-reentry-r4-terminal-review-1791092645025522000.json`。このHTTP401は非credentialのPAR対照であり、stock claimやOAuth成功を証明しない。stock PAR/session/logoutと5bのgateは残る。
