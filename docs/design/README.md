# FAPI 2.0デモの設計資料

この資料は、3rd PartyのKongでOAuth・セッションを管理し、独立した3rd PartyバックエンドからAPI提供者のKongへ接続する承認済み設計を説明します。**バックエンド追加のソース・ローカル検証は完了し、新経路の実行受入は未実施です。** WP1～WP6とEpic #6の受入はバックエンド追加前の構成に対する履歴です。FAPI 2.0完全準拠や認定を主張しません。

## 最初に読む資料

- [3rd Partyバックエンド分離の影響と対応計画](third-party-backend-change-plan.md): 2026-10-13に承認された構成見直し。図・文書を先行し、コードを別ブランチで実装・受入する。
- [アーキテクチャと検証範囲](../../ARCHITECTURE.md): 全体構成、Route A/B、対応済み制御と残る差分、追加設計。
- [デモの起動・再現手順](../../README.md): 既存2 control planeとGit外入力を再利用する手順。
- [お客様向け説明](third-party-demo-explainer.md): 標準機能、デモ固有の補完、説明すべき制約。
- [FAPI要件の詳細対応表](third-party-fapi2-conformance.md): 主要要件、優先度、検証ID。
- [WP5受入表](third-party-wp5-acceptance.md) / [WP6受入表](third-party-wp6-acceptance.md): 統合・UI・切替・再現の結果と未網羅範囲。

## 実装契約と検証履歴

- [バックエンド分離構成の準備・適用・受入](third-party-backend-runtime.md): 新identity、schema2承認、native実行と未実施境界。

- [3rd Party経由デモ要件](third-party-fapi2-requirements.md): 承認済みトポロジーと実装・受入の境界。
- [AS mTLS補完契約（DP0）](third-party-as-mtls-transport.md): 固定版の挙動、送信境界、証明書identity、bridgeとの分担。
- [AS側peer証跡の契約](third-party-as-peer-evidence.md): 試験専用observerの観測・相関・出力。
- [WP1基盤設計](third-party-foundation-design.md): 2 control plane、PKI、Route UUID、foundation/runtimeの分離。
- [WP2隔離実行結果](third-party-wp2-runtime-evidence.md): Keycloakクライアント・トークン・introspectionの検証。
- [検証履歴](verification-history.md): 完了した隔離試験、失敗試行、一次receipt。実行前プレビュー5件を統合した記録。
- [開発計画](third-party-delivery-plan.md) / [実装移譲契約](third-party-luna-handoff.md): 作業分担と受入境界の履歴。
- [v1デモ要件](fapi2-keycloak-requirements.md): 初期構成。現行要件で変更していない箇所に適用。
- [障害対応記録](../troubleshooting-log.md): 失敗の原因、対応、検証結果。

## 構成図とフロー図

図はJSONソース、HTML、PNGを`workflows/`に保存します。新版は同じ3rd Party境界内でKong・静的UI・業務バックエンドの役割を分け、バックエンドからAPI提供者側Kongを呼ぶ承認済み設計を表します。図の検証と新構成の実行受入は別です。

| 図 | JSON | HTML | PNG | 状態 |
|---|---|---|---|---|
| 3rd Party経由の全体構成 | [ソース](workflows/third-party-architecture.architecture.json) | [Pagesで閲覧](https://picketfence-labs.github.io/diagrams/16c30c21e271/) | [画像](workflows/third-party-architecture.architecture.png) | 承認済み設計・実装／受入前 |
| Route A: mTLS | [ソース](workflows/route-a-mtls.workflow.json) | [Pagesで閲覧](https://picketfence-labs.github.io/diagrams/697f14e71ed9/) | [画像](workflows/route-a-mtls.workflow.png) | 承認済み設計・実装／受入前 |
| Route B: PKJWT + mTLS | [ソース](workflows/route-b-pkj-mtls.workflow.json) | [Pagesで閲覧](https://picketfence-labs.github.io/diagrams/31aaf1787cd8/) | [画像](workflows/route-b-pkj-mtls.workflow.png) | 承認済み設計・実装／受入前 |

新版は新しいPages URLへ公開しました。公開HTML3件はHTTP200で、凍結したローカルHTMLとSHA-256が一致しています。旧図のPages URL（[全体](https://picketfence-labs.github.io/diagrams/b671e37f23de/)・[Route A](https://picketfence-labs.github.io/diagrams/55b6534fdb5b/)・[Route B](https://picketfence-labs.github.io/diagrams/d4d6f772e970/)）はバックエンド追加前の履歴として維持します。reset/logout専用図は削除済みですが、実行時のlogout機能と受入記録は維持します。

全体構成図とRoute A/B図の本文は日本語です。Archify 2.17の固定Viewer UIとHTMLの言語属性は日本語に対応せず英語へフォールバックします。新版3図のartifact検証9/9（error・warningとも0）、4サイズの表示検証、明暗画像とPNGの目視確認が通過しました。結果は、[全体構成receipt](workflows/third-party-architecture.receipt.json)、[Route A receipt](workflows/route-a-mtls.receipt.json)、[Route B receipt](workflows/route-b-pkj-mtls.receipt.json)へ分けて記録しています。

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
- [ADR 0023](../decisions/0023-third-party-backend-separation.md): UI配信と業務API呼出しの分離、内部mTLSとRoute鍵の境界。

初期判断は[ADR 0006](../decisions/0006-fapi-custom-plugin-ghcr-logout.md)、[ADR 0007](../decisions/0007-keycloak-only-fapi2-demo.md)、[ADR 0008](../decisions/0008-route-b-endpoint-auth-split.md)に残しています。
