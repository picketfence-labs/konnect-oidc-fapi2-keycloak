# ADR 0013: schema準備とruntime受入をWP間で分ける

- Status: Proposed（PR #5 merge済み。PR #13で開発移譲用の分担補足をレビュー）
- Date: 2026-10-02
- Amends: [Delivery plan](../design/third-party-delivery-plan.md)のWP1/WP5の成果物分担
- Preserves: [ADR 0012](0012-third-party-as-mtls-transport.md)の方式、P0、spike、preflightとlive承認ゲート

## 問題

WP1はGateway別decK stateと差分確認を担当する。一方、DP0のglobal transport entityとbridgeの`transport_delegate`設定にはcustom schemaが必要になる。現行`scripts/plugin-schema.sh`は1つのCPのbridgeだけを確認し、schema未登録時に`scripts/deck.sh`を停止する。実際にschema欠落でdiffが停止した履歴もある。

新schemaをWP5まで作らないと、WP1のdiff受入がWP5に依存する。しかしWP5はWP1、WP2、WP3に依存している。schema準備とruntime本体を分けて、この循環を解消する。

## 決定

1. WP1が、DP0の固定された設定形に従うself-containedな`fapi-as-mtls-transport/schema.lua`を作る。既存bridge schemaにも`assertion_delivery: transport_delegate`を追加する。schemaのdefaultや旧header modeとの互換性を明記する。WP1ではtransport handler、signer delegate、observerを実装しない。
2. WP1が、`GATEWAY=api|third-party`に基づくCP選択をschema check/syncにも適用する。third-partyでは両schemaを確認し、APIには両custom pluginのEntityを配置しない。登録済みschemaの存在とDPでのpluginロードは別々に判定する。schema syncはKonnectの書き込みであり、利用者の承認後にだけ行う。
3. WP1の静的検証は最終構成の宣言を照合する。third-partyの両plugin必須、APIの両plugin禁止、bootstrap値、global transport Entityが有効な1件、Route UUIDとidentity mappingを確認する。schemaだけのimageや成功を返す仮handlerを作らない。transport本体が未実装の間は通常入口/UIを開かず、起動可能とは説明しない。
4. WP1のplan/diffは、承認済みの基盤適用とschema登録が必要なら、その前提を明記する。mockによる対象CP選択テストをlive diffの成功に置き換えない。未承認の前提は`blocked:environment-approval`、未取得の証跡は`not_run`と記録する。WP1を完全受入済みとは扱わない。
5. WP5は最初にAS-MTLS-OBS-01を通し、その後にtransport handler、bridge signer delegate、全worker preflight、実TLS/lifecycle/drift検証を実装する。WP1のschemaと本体が一致しない場合はschemaを含む設計差分を明示する。既存のspike停止条件を弱めない。
6. Issueは設計ready、依存受入、環境承認、実装レビュー、runtime受入を分けて記録する。依存WPの完全受入前に後続WPを開始しない。PR mergeだけでIssueをcloseしない。

## 検証と影響

- WP1でGateway未指定/不正値、CP ID/名前の不整合、schema未登録、不正global設定を非zeroで拒否する。入力不正は資格情報読み込みやネットワークアクセス前に拒否する。
- WP1でschemaの許可値、秘密値inline禁止、Route identity重複、global scopeを検証する。schema/static成功はTLS/署名/lifecycleの証明ではない。
- Terraformは既存`konnect_gateway_control_plane.demo`と既存DP resource addressを保持する。追加CPのDP鍵・証明書生成resourceとlocal sensitive fileは基盤追加の一部。既存CPの削除/再作成、既存DP鍵の意図しない更新は許可しない。
- WP5のruntime preflightはWP1の静的検証に追加する。全workerの実ロード、wrapper、registry epoch、Route/config一致と通常入口閉鎖を確認する。
- 新しい本番監視基盤、追加proxy、Docker起動やKonnectへの適用承認は、このADRから導かない。

## 正本

- [Luna / High開発移譲契約](../design/third-party-luna-handoff.md)
- [AS mTLS補完契約](../design/third-party-as-mtls-transport.md)
- [AS peer証跡契約](../design/third-party-as-peer-evidence.md)
- [既存schema欠落の記録](../troubleshooting-log.md)
