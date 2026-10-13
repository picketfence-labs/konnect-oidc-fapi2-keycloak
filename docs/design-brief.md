# 設計概要

このデモは、3rd PartyサービスからKeycloakの認可を経て保護APIを呼び出し、mTLSと`private_key_jwt`のクライアント認証、証明書に束縛されたトークンを比較します。3rd PartyのKong GatewayとAPI提供者のKong API Gatewayを別々のKonnect control planeで管理します。

全体構成、Route A/B、FAPI対応範囲は[ARCHITECTURE.md](../ARCHITECTURE.md)、実装契約は[3rd Partyデモ要件](design/third-party-fapi2-requirements.md)、操作手順は[README](../README.md)、詳細資料は[設計資料一覧](design/README.md)を参照してください。

## バックエンド分離の承認済み設計

UIをTP Kong経由で配信し、業務要求をTP Kong→TPバックエンド→API側Kong→Resource Serverへ分離します。OAuth/セッションはTP Kongに残し、内部hopには専用mTLS identity、外部APIにはASで使った同じA/B証明書を使います。PR #31はmainへマージ済みで、利用者はHTTP E2Eの確認範囲で受け入れ、今回の作業を完了しました。[ADR 0023](decisions/0023-third-party-backend-separation.md)に構成判断、[ADR 0024](decisions/0024-third-party-backend-e2e-acceptance.md)に受入範囲と未検証項目を記録しています。

## 変更前の到達点

WP1～WP6とEpic #6は合意した範囲で受入済みです。認証、API応答、署名・claim/header・証明書束縛、偽装拒否、logout、既存2 control planeを使うclean checkout再現を確認しています。試験の層と未検証項目は[WP5受入表](design/third-party-wp5-acceptance.md)と[WP6受入表](design/third-party-wp6-acceptance.md)に記録しています。

FAPI 2.0完全準拠や認定を主張しません。Route BのPAR form `client_id`省略、revocation metadata URL、`iss`欠落拒否、認可開始CSRF等の差分を開示します。

## 維持する設計境界

- 認証済み`department` claimをヘッダーと論理ルートへ反映し、偽装値を信頼しない。
- A/Bを別Route・Service・証明書・セッションに分離する。
- 標準OIDCを基礎に固定版で必要なPKJWT/mTLSを補完する。Kong coreをforkしない。
- API入口でintrospectionとPoPを検査し、保護APIで署名と元クライアント証明書への束縛を再検証する。
- 保護APIへ検証用Bearer tokenを転送する。Cookieと内部assertion用ヘッダーは除去する。
- 秘密値と一次receiptはGit外に保持し、UIは許可された結果だけを表示する。

## 設計の履歴

2026-09-22にAuth0による初期デモを検証し、Keycloakを使う二経路のv1へ移行しました。2026-10-02以降は3rd PartyのクライアントGatewayを追加し、API側をResource Serverの入口へ変更しました。旧契約は[v1要件](design/fapi2-keycloak-requirements.md)、変更判断は[ADR 0009](decisions/0009-third-party-client-gateway-topology.md)以降に保持します。

前回の資料整理では、全体構成図の利用者確認後、Route A/B図へ3rd Partyのswimlaneを追加しました。実行時の構成変更、Control Plane適用、Docker変更は行いません。
