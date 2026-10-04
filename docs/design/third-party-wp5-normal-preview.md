# WP5通常デモの統合プレビュー

## 現在地

PR #21は利用者がmerge済み。main `9243886603a225c3f86d1be602fabe99ff76b6ea`で`make validate`と`make test-wp5-transport`を独立確認し、いずれもPASS。mainのconfiguration CIとimage build/publishも成功した。隔離ASの受入結果は[WP5受入表](third-party-wp5-acceptance.md)を参照する。通常デモの起動・同期・ブラウザーフローはまだ実行していない。

目的はKong標準を優先する顧客要件デモ。stock PAR/revoke本文を維持し、RFC 9126のclient_id gapは記録のみ。本番FAPI完全準拠のための機能追加はしない。

## 読み取り専用の確認結果

| 対象 | 最新差分・結果 | 適用で変わること |
|---|---|---|
| API CP / WP3 | create6 / update0 / delete13 | 旧A/BのService・Route・pluginと旧Route証明書2件を除去し、Resource ServerのService・Route・pluginを追加 |
| third-party CP / WP5 | create11 / update0 / delete0 | A/BのService2、Route2、Service plugin7を追加 |
| CPの基盤 | foundationとcustom schemaの照合成功 | APIの共有CA、用途別基盤証明書、third-partyのglobal transportは維持 |
| 通常Compose | configの展開成功 | Keycloak、verifier、API DP、third-party DP、UIを使用 |
| ローカルPKI | 10 identityの期限・鍵一致・CA署名がPASS | 既存鍵を保持。証明書や鍵をGitへ追加しない |
| 現在のコンテナ | このデモのコンテナなし | 他プロジェクトの停止済みコンテナは対象外 |
| Keycloak | 保存済みH2あり。生成realmにはPS256 providerを宣言 | 既存realmの再importを期待せず、管理対象のPS256 providerを追加・照合 |

API state SHA-256は`8c765f66029c760c2b0316c4e7fc9d688359f02d574d37dc9b3e37e063b84465`、diff SHA-256は`5afa9dae3456a4de041f24d9440332df1ada705269dcf11cad793df76f806111`。仕上げPRで追加entityのIDを固定したthird-party state SHA-256は`f7217b4409d259c942a51e0ddb717d2b613b2e6a0734714e0a55bf2731bb3b3e`。role input hashは既存プレビューから不変。通常preflightの一次証跡はGit外の`.generated/evidence/wp5-normal-preflight-1791111787699052000.json`に保持する。

third-partyの追加差分は`--parallelism 1`で取得し、報告件数と列挙entityの一致を検査する。標準の並列設定で件数11に対して列挙10件となる例があったため、guardを緩めず直列化する。レビュー後の同期は`WP5_THIRD_PARTY_RUNTIME_APPROVED=YES`と、mode0600の`.generated/evidence/wp5-third-party-runtime-approval.json`が必要。記録はtarget・state・role・完全なdiffのhash、操作一覧を結び付け、適用直前にも同じ結果を要求する。記録を自動承認したり、未承認で同期したりしない。

最終wrapperの連続2回のread-only diffは、操作11件と全hashが一致した。diff SHA-256は`f228e3bba0625e8ef7c3526316787513358d2628c0b747b7ce541ef34d7bb725`。一次証跡は仕上げworktreeの`.generated/evidence/wp5-final-normal-diff-review-20261004.json`に保持する。DECK変数をmaskしないJSONはメモリ内だけでhash化し、本文・secretを出力しない。適用承認はまだ記録していない。

## 起動に使うimage

main `9243886`の公開済みimageを使い、手元で再buildしない。

| image | 公開index digest |
|---|---|
| Kong | `sha256:4d152ec6c035db6c72155f7a8a2fedadb4c3ff2b529029298cfedac0ac110077` |
| PoP verifier | `sha256:e7f129e2f863830c17faec256a57d64a250ef85ec99800d49491aa6187e2cb89` |

両方のtagは`sha-9243886603a225c3f86d1be602fabe99ff76b6ea`。KeycloakはComposeで固定された標準26.7.4を使い、observer imageは通常環境へ入れない。

## レビュー後の実行順序

1. 通常同期の仕上げPRを人がレビュー・mergeする。このプレビューのCP差分とDocker起動を確認してから実行する。
2. `make generate-dev-assets`の後に`make render-runtime`を実行する。前者がruntime secretファイルを再生成するため、CP endpointの描画は後に行う。既存鍵・資格情報・H2を保持する。
3. 標準Keycloakだけを起動し、管理対象3 clients、realm設定、PS256 providerの最新planを確認する。想定外の対象・差分があれば適用前に止める。
4. 確認したKeycloak差分を反映する。既存の別providerやlegacy clientは削除しない。
5. API/third-partyの最新decK diffを照合し、承認されたtarget・state・role・diffだけを同期する。旧API経路を置換するため、復旧用の既存状態はGit外に保存する。
6. 配布済みimageをpullし、`--no-build --pull never`でverifier・API DP・third-party DPを起動する。third-partyのcontainer listenerは明示的に`0.0.0.0:8443 ssl`、host mappingは`127.0.0.1:18443`とする。UIと通常入口8443は閉じたままにする。
7. `scripts/require-wp5-readiness.sh --wait`で全workerを確認し、`FAPI_DEMO_PROXY_LISTEN='0.0.0.0:8443 ssl' scripts/require-wp5-readiness.sh --supervise`で入口とUIを開く。worker状態が変わればsupervisorが入口・UI・third-party DPを閉じる。
8. A/Bの認証→API→Upstream、認証済みclaim、header除去、PoP、提示iss不一致、更新・ログアウト、入口の再閉鎖を確認する。通常環境で未実行の検査を隔離fixtureの成功で代用しない。

`make up`の既定経路はまだ閉鎖を維持する。通常統合が成功するまでIssue #9/#11を完了扱いにしない。WP6のUI/E2E自動化・clean checkout手順は別WPである。
