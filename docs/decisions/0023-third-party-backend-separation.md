# ADR 0023: 3rd PartyのUI配信と業務API呼出しを分離する

- 状態: 承認済み設計・実装／受入前
- 日付: 2026-10-13
- 関連: [対応計画](../design/third-party-backend-change-plan.md)、[全体構成](../../ARCHITECTURE.md)

## 背景

変更前はUIを独立したnginxから配信し、TP KongがOAuth処理とAPI提供者側Kongへの転送を担っていた。利用者が求める3rd Partyの業務バックエンドが存在しない。UI提供と外部API呼出しを別の役割へ分ける必要がある。

## 決定

ブラウザーの共通入口をTP Kongとする。静的UIはTP Kongから内部HTTPで取得する。業務要求はブラウザー→TP Kong→TPバックエンド→API側Kong→Resource Serverとし、応答は逆順に返す。バックエンドの外向き要求はAPI側Kongへ直接送信し、TP Kongへ戻さない。

OAuth、PAR、PKCE、コード交換、セッション、refresh、logoutはTP Kongが担当する。Kong→バックエンドは専用mTLS identityで認証し、利用者ごとのアクセストークンを内部だけで渡す。バックエンドは固定A/B pathから証明書を選び、固定APIだけを呼び出す。

ASへのA/B identityと、API呼出し時の送信者制約を維持するため、A/BのTLS証明書・秘密鍵をKongとバックエンドの同じOAuthクライアント信頼領域で共有する。内部hop専用Certificate entityを追加し、A/B entityを置換しない。JWT署名用JWK、metadata鍵、refresh token、Cookieをバックエンドへ渡さない。

## 影響と検証

鍵の保持箇所が増える。限定した読み取り専用mount、バックエンドの非公開入口、専用peer照合、任意URL・redirect拒否、応答allowlist、秘密非露出で境界を定める。別の証明書でAPIを呼び出すと`cnf.x5t#S256`に一致しない。OAuth全体をバックエンドへ移す方式は今回採らない。

ASへA/B identityが提示され、バックエンドには内部hop専用identity、APIには同じA/B identityが提示されることを新経路で観測する。refresh/logout、同時A/B、backend停止、迂回・偽装・漏洩の負例も新たに受入する。

資料と図をコードより先にmainへ提供し、実装／受入前と表示する。変更前のWP1～WP6受入とPagesは履歴として維持し、旧receiptを新経路の成功証跡に流用しない。コードは別ブランチ・別PRで実装する。
