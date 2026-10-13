# ADR 0024: バックエンド分離デモをHTTP E2Eの確認範囲で受け入れる

- 状態: 利用者承認済み・今回の作業を完了
- 日付: 2026-10-13
- 関連: [ADR 0023](0023-third-party-backend-separation.md)、[受入結果](../design/third-party-backend-runtime.md#新経路の受入結果2026-10-13)、[障害対応記録](../troubleshooting-log.md)

## 背景

バックエンド分離の実装は[PR #31](https://github.com/picketfence-labs/konnect-oidc-fapi2-keycloak/pull/31)で利用者がmainへマージした（`8b9c47a`）。受入したheadは`1f2b634`で、最終CIは3件すべて成功した。利用者は「最低限end-to-endの確認が取れていればOK」とし、実サービスを使ったHTTP E2Eの結果と実ブラウザー表示の未確認を説明した後、「ではOKです」と終了を指示した。

## 決定

今回のnative-sourceデモは、HTTPクライアント→TP Kong→バックエンド→API側Kong→Resource Serverと、実Keycloakを使う認証を通したE2Eの範囲で受け入れる。マージ前に実行した結果を受入証跡とし、終了記録のための再起動・再認証・追加の網羅検証は行わない。

| 確認対象 | 結果 |
|---|---|
| 2利用者×Route A/Bの4セッション | API200、13項目のidentity・claim/header・署名・証明書束縛等の照合に成功 |
| 有効期限越えの継続・logout | 300秒＋35秒後も同じCookieJarで全4件API200、logout後は保護APIが302 |
| 入力と証明書の負例・対照 | Authorization16件、API提供者側の直接検査7件、専用hop以外のBackend401拒否が成功 |
| Backend停止時の入口閉鎖 | 正常GET200/Backendready後の意図的停止でmarker除去、forwarder終了、8443接続拒否、UI/Backend/TP停止を確認 |
| 終了状態 | 候補6・原5サービスは停止、公開5ports閉鎖、残留process0、原DB/PKI/入力のmode・mtime・digest不変 |

## 未検証範囲と残る制約

実JavaScriptブラウザーの画面操作・表示は既存CAの信頼エラーで未確認。AS wire上の認証方式・提示identity・refresh grant、rotation/revocation、新構成のclean bootstrap・公開Backend image・他OS、任意config/generation drift・restartの実障害注入も未検証として残す。機能上の期限越え継続やBackend停止の成功でこれらを代替しない。

既存IDtoken fragmentのUIへの返却と即時除去、FAPI適合の既知差分を維持する。stock OIDCのPEM読込障害の根本原因、TP/APIのCompose管理hash差の原因は未確定。初回IdP更新時のbefore/after pair消失もUNKNOWNとして保持する。今回の受入で完全FAPI準拠・認定・本番運用適合を主張しない。

## 証跡と再開条件

一次証跡はコード用worktreeのGit外`.generated/evidence/tp-backend-runtime-20261013/`に保持する。`core-live-acceptance.json`、`provider-live-result.json`、`readiness-fail-closed.json`、`closure-only-final-cleanup.json`、`coordinator-final-summary.json`が要約で、private raw・失敗snapshot・候補container/networkも保全する。秘密値や管理APIのraw応答をGitへ追加しない。

今回の作業に追加必須の検証は残さない。再開する場合は目的と上記未検証項目を選び、既存候補・CP設定・素材との整合を確認する。Docker起動、CP rollback・同期、DB再構成、証明書変更などの操作は今回の終了記録とは分け、具体的なプレビューと利用者の意図を確認して扱う。
