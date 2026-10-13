# ADR 0017: 公開済みKeycloak runtime JARからWP5試験observerを作る

- 状態: 試験専用imageのbuild方式、固定パス照合、direct observerの検証を採用済み
- 日付: 2026-10-04
- 範囲: WP5 5aの試験専用Keycloak peer observer

この判断時点では5a全体は未完了だった。その後の再入r4、stock v15、直結transport、通常統合は[検証履歴](../design/verification-history.md)と[WP5最終受入表](../design/third-party-wp5-acceptance.md)を参照する。

## 背景

承認済みfull-reactor v2/v3はcompile exit1で停止した。v3の原因は未確定で、observerソースの不正を証明していない。固定版26.7.4の公開runtime JARでhandlerを特定し、2ソースの`--release 17`コンパイルと、公式imageとのclasspath一致を確認した。

direct TLS v2は39/40だったが、ON scanの22行すべてが`observer_failure`で、endpoint/method/pathは不明、相関IDとpeer metadataはなく、対応付け0件だった。公開Quarkus 3.33.3.2 JARの`UriInfoImpl.getPath(false)`がrequest contextを読む前に`IllegalArgumentException`を投げることを、bytecode解析とオフラインJava実行で確認した。runtime receiptに例外クラスは残していないため、これはソース上の欠陥と原因の説明であり、同例外をruntimeで採取した証拠ではない。

## 決定

ローカルの3段階buildを使う。digest固定Keycloakから公開runtime JARと依存を取得し、digest固定Temurin 21でhandler patchとpackage-private observerを`--release 17`・annotation processing無効でコンパイルする。変更したruntime JARだけを同じ固定Keycloak imageへ戻す。入力identity、handler ABIとhook順序、handler置換とhelper追加以外のarchive不変を検証する。製品用imageとして公開しない。

パスは解決済みVert.xの`RoutingContext.request().path()`だけから取得し、固定5個の絶対`/realms/fapi-demo/...`パスを照合する。固定HTTP method/endpointと先頭slashなしのcanonical pathを記録する。`UriInfo.getPath(false)`、query string、対象外パスは読まない。

修正版v3はTemurin 21でbuildに成功した。独立archive/bytecode reviewではclasspath JAR471個中470個が不変、handler1個置換とhelper1個追加、他のruntime entry256個が不変、class major61、handler ABI/hook順序不変を確認した。runtime JAR SHA-256は`3ef3660cf08ed1ca8b627852a4ddf625e05c18b189680e9bf38e0d9b08b4ded2`、imageは`sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953`。

host JDK23の`--release 17`でも公開JAR471個に対するコンパイルと固定パス50対照を通過した。direct fixture v3は40/40、peer対応付け18件、OFF行0、OFF/ON HTTP状態8組一致、TLS負例4種類と前後対照、全対象log scan、後片付けを独立確認した。一次receiptは`/private/tmp/wp5-as-mtls-observer-run-receipt-20261004-v3.json`、SHA-256 `93f3503abff52ee38449130bc131484664d0c96f8ad35e45b8a6f4924b97709c`。reviewは`.generated/evidence/wp5-root-direct-terminal-review-1791085120188078000.json`。失敗したv1/v2は成功へ書き換えない。

## 影響

公開runtime/dependency入力を維持し、Git・APT・Maven・無関係なreactor moduleをbuildから除外した。imageは別途レビューした隔離試験専用であり、通常Compose、realm更新、Control Plane変更を承認するものではない。full-reactor v3の失敗原因は未確定のまま記録する。
