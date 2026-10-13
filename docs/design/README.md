# FAPI 2.0デモの設計資料

現在の対象は、3rd PartyのKongをOAuthクライアント、API提供者のKongをResource Serverの入口として使う構成です。WP1～WP6とEpic #6は合意したデモ範囲で受入済みです。FAPI 2.0完全準拠や認定を主張しません。

## 最初に読む資料

- [アーキテクチャと検証範囲](../../ARCHITECTURE.md): 全体構成、Route A/B、対応済み制御と残る差分、追加設計。
- [デモの起動・再現手順](../../README.md): 既存2 control planeとGit外入力を再利用する手順。
- [お客様向け説明](third-party-demo-explainer.md): 標準機能、デモ固有の補完、説明すべき制約。
- [FAPI要件の詳細対応表](third-party-fapi2-conformance.md): 主要要件、優先度、検証ID。
- [WP5受入表](third-party-wp5-acceptance.md) / [WP6受入表](third-party-wp6-acceptance.md): 統合・UI・切替・再現の結果と未網羅範囲。

## 実装契約と検証履歴

- [3rd Party経由デモ要件](third-party-fapi2-requirements.md): 現行トポロジーの実装契約。
- [AS mTLS補完契約（DP0）](third-party-as-mtls-transport.md): 固定版の挙動、送信境界、証明書identity、bridgeとの分担。
- [AS側peer証跡の契約](third-party-as-peer-evidence.md): 試験専用observerの観測・相関・出力。
- [WP1基盤設計](third-party-foundation-design.md): 2 control plane、PKI、Route UUID、foundation/runtimeの分離。
- [WP2隔離実行結果](third-party-wp2-runtime-evidence.md): Keycloakクライアント・トークン・introspectionの検証。
- [検証履歴](verification-history.md): 完了した隔離試験、失敗試行、一次receipt。実行前プレビュー5件を統合した記録。
- [開発計画](third-party-delivery-plan.md) / [実装移譲契約](third-party-luna-handoff.md): 作業分担と受入境界の履歴。
- [v1デモ要件](fapi2-keycloak-requirements.md): 初期構成。現行要件で変更していない箇所に適用。
- [障害対応記録](../troubleshooting-log.md): 失敗の原因、対応、検証結果。

## 構成図とフロー図

図はJSONソース、HTML、PNGを`workflows/`に保存します。全体構成図は2026-10-13に利用者確認済みです。Route A/Bも更新し、利用者とAPI Gatewayの間へ3rd Partyのswimlaneを追加しました。同じlane内でサービスUIとKong Gatewayの処理を分けています。

| 図 | JSON | HTML | PNG | 状態 |
|---|---|---|---|---|
| 3rd Party経由の全体構成 | [ソース](workflows/third-party-architecture.architecture.json) | [Pagesで閲覧](https://picketfence-labs.github.io/diagrams/b671e37f23de/) | [画像](workflows/third-party-architecture.architecture.png) | 利用者確認済み・公開済み |
| Route A: mTLS | [ソース](workflows/route-a-mtls.workflow.json) | [Pagesで閲覧](https://picketfence-labs.github.io/diagrams/55b6534fdb5b/) | [画像](workflows/route-a-mtls.workflow.png) | 3rd Party構成へ改訂・公開済み |
| Route B: PKJWT + mTLS | [ソース](workflows/route-b-pkj-mtls.workflow.json) | [Pagesで閲覧](https://picketfence-labs.github.io/diagrams/d4d6f772e970/) | [画像](workflows/route-b-pkj-mtls.workflow.png) | 3rd Party構成へ改訂・公開済み |

2026-10-13に全体構成図をPagesへ公開し、Route A/Bも既存URLのまま改訂版へ更新しました。公開HTMLはローカルHTMLとSHA-256が一致しています。reset/logout図はこのリポジトリから削除しました。実行時のlogout機能と受入記録は維持します。

全体構成図とRoute A/B図の本文は日本語です。Archify 2.17の固定Viewer UIとHTMLの言語属性は日本語に対応せず英語へフォールバックします。1440×900、1600×1000、1920×1080、2048×1320の表示検証が通過し、最小・最大サイズの明暗画像を実際に確認しました。artifact検証と画像レビューは、[全体構成receipt](workflows/third-party-architecture.receipt.json)、[Route A receipt](workflows/route-a-mtls.receipt.json)、[Route B receipt](workflows/route-b-pkj-mtls.receipt.json)へ分けて記録しています。

## 主な設計判断

- [ADR 0009](../decisions/0009-third-party-client-gateway-topology.md): 3rd PartyクライアントGateway。
- [ADR 0010](../decisions/0010-api-gateway-resource-server-validation.md): API側の検証。
- [ADR 0011](../decisions/0011-customer-demo-scope.md): 顧客向けデモの範囲。
- [ADR 0012](../decisions/0012-third-party-as-mtls-transport.md): AS mTLS補完。
- [ADR 0013](../decisions/0013-work-package-schema-and-acceptance-boundaries.md): schema準備と実行時受入の分担。
- [ADR 0014](../decisions/0014-reuse-existing-api-ca.md): 既存CA再利用。
- [ADR 0015](../decisions/0015-api-resource-server-header-boundary.md) / [ADR 0016](../decisions/0016-api-gateway-inbound-tls-policy.md): ヘッダー境界とAPI入口のTLS。
- [ADR 0020](../decisions/0020-normal-demo-runtime-sync.md) / [ADR 0021](../decisions/0021-wp5-revocation-metadata-gap.md): 通常統合とmetadata差分。
- [ADR 0022](../decisions/0022-final-documentation-layout.md): 最終構成に合わせた資料整理。

初期判断は[ADR 0006](../decisions/0006-fapi-custom-plugin-ghcr-logout.md)、[ADR 0007](../decisions/0007-keycloak-only-fapi2-demo.md)、[ADR 0008](../decisions/0008-route-b-endpoint-auth-split.md)に残しています。
