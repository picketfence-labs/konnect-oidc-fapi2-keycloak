# ADR 0020: 通常デモへのruntime反映

- 状態: 実装レビュー中。通常環境の適用・受入は未実施
- 関連: [ADR 0013](0013-work-package-schema-and-acceptance-boundaries.md)、[通常統合プレビュー](../design/third-party-wp5-normal-preview.md)

## 背景

PR #21でAS transportと隔離検証はmainへ反映された。通常デモではthird-party同期が一律無効のままであり、保存済みKeycloak realmへはrealm importだけで追加のPS256 providerが反映されない。これらを通常統合の前に解消する。

## 決定

third-partyのruntime同期は、明示的な実施意図と、対象・state・role input・差分を結び付けた非公開のレビュー記録が一致するときだけ許可する。同期直前に最新diffと入力を再照合する。許可する操作はA/Bの固定Service2・Route2・Service plugin7の追加だけであり、基盤の更新・削除や別entityの置換は許可しない。追加entityのUUIDもstateで固定し、毎回のID生成でdiffが変わることを防ぐ。変更なしの確認はread-only diffで行い、syncを自動再試行しない。

Keycloakは標準のcomponents Admin APIで、realm templateにある管理対象のPS256 `rsa-generated` providerだけを追加または照合する。管理対象の設定差分を更新する場合も、他providerと未知のconfigを維持する。重複名や別typeとの衝突は適用前に停止する。既存H2、鍵、資格情報、legacy clientsを削除しない。

起動は公開済みmain imageと既存Composeを使い、全worker readinessを確認してから既存supervisorで通常入口とUIを開く。通常統合の成功はAS隔離検証とは別に記録する。

## 範囲

顧客要件デモの起動・同期を仕上げる変更である。stock PAR/revoke本文、RFC 9126 gapの扱い、AS認証方式、本番FAPI適合を目的としないという決定は維持する。
