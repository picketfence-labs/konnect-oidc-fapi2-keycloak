# ADR 0009: 3rd Partyをclient Gatewayとして分離する

- Status: Proposed
- Date: 2026-10-01
- Amends: [ADR 0007](0007-keycloak-only-fapi2-demo.md)の決定7・8（KongがRelying PartyとPoP検証の前段を兼ねる構成）

## Context

追加要件として、ClientとKong Gatewayの間に3rd Partyを置く。3rd PartyはKeycloakとの認可コードフローでtokenを取得し、Kong Gateway経由でUpstream APIへアクセスする。3rd Partyを含むmTLS/PKJWTの顧客向け動作デモのため、Kong GatewayをAPI向けとは別に立てる（3rd PartyでKongを使うことは必須ではない）。

v1（現行main）のKong Gatewayは、FAPI client（PAR、client認証、code exchange、session）と、Upstreamの前段の両方を担っている。3rd Partyを追加すると、この2つの役割は別々の組織に属する。

目的・優先順位は[ADR 0011](0011-customer-demo-scope.md)で更新した。完全適合を完成条件にはしない。

## Decision

1. FAPI clientの役割を、新設の**3rd Party Gateway**（Kong Gateway 3.16.0.0）へ移す。v1のRoute A（`tls_client_auth`）とRoute B（`private_key_jwt` + custom plugin）は、両方とも3rd Party Gatewayで維持する。
2. 既存のKong Gatewayは**API Gateway**（Resource Server）とし、clientとしての機能を持たせない。
3. UIからKongへの直接経路は残さず、3rd Party経由の経路で置き換える。
4. 2つのGatewayは、別々のKonnect control planeで管理する。既存のcontrol planeはAPI Gateway用として再利用し、3rd Party用のcontrol planeをTerraformで追加する。
5. sender constraintは、両区間ともmTLS certificate-bound tokenで統一する。必須経路にDPoPは使わない。追加候補の設計調査はDP1で分ける。
6. 3rd Party GatewayはRoute別のclient certificateを、KeycloakのPAR/token/refresh/revoke endpointとAPI Gatewayへ提示する。metadata取得は専用certでmTLS化する（DP0/ADR 0012）。認証POSTとAPI呼出しは同じRoute certificateであり、metadata certとは別にする。
7. 本来のFAPI 2.0要件と今回の優先度は、実装に依存しない形で[conformance文書](../design/third-party-fapi2-conformance.md)へ定義する。3rd Party GatewayはそのKongによる実装例と位置付ける。
8. Kong stockで充足しない`iss`欠落検査と開始CSRF追加防御は将来対応として開示する。提示されたissの不一致検査とstate/PKCEは維持する。

## 両Routeを維持する理由

client認証は、3rd Party GatewayとKeycloakの間で閉じる。API Gatewayが検証するのは、tokenの有効性と`cnf.x5t#S256`（tokenとcertificateの束縛）だけであり、client認証の方式は結果に影響しない。FAPI 2.0 Security Profile §5.3.3.1は、mTLSと`private_key_jwt`の両方をclient認証として認める。したがって、構成変更後も両Routeは妥当な選択肢である。

- Route Aは、1枚のcertificateでclient認証とtoken bindingを兼ねる。構成が簡単である。
- Route Bは、client identity（署名鍵）とTLS終端（certificate）を分離できる。実運用のエコシステムで採用例がある（豪州CDRなど）。

## Consequences

- API Gatewayの検証ポリシーは1つになる。Routeによる差分は、3rd Party GatewayとKeycloak clientの側に閉じる。
- Konnect control plane、data plane certificate、decK stateがそれぞれ2つになる。`make`の各targetは対象Gatewayを明示する必要がある。
- Keycloak clientのIDを、3rd Partyを表す名前へ置き換える（`third-party-fapi-mtls`、`third-party-fapi-pkj-mtls`）。
- v1の受入シナリオのうち、PoP verifierでの検証（`A-POP-01`、`B-POP-01`、`POP-01`、`POP-02`）は、API Gatewayでの検証へ移る。
- custom pluginの単純移設ではAS全back-channel mTLSを満たせない。DP0/ADR 0012で専用AS transportとbridge送信時delegateを選択した。独立レビュー・merge後にWP5で実装する。

## Alternatives considered

| 案 | 不採用の理由 |
|---|---|
| 既存の直接経路を残して並存させる | Gatewayが2つの役割を兼ねる構成が残り、組織境界が曖昧になる。検証対象も倍になる |
| 3rd Party Gatewayを、Konnectに接続しないDB-less Kongにする | 「別組織」であることを表しにくい。構成の配布方法が2系統になる |
| 3rd Party区間だけDPoPにする | API Gatewayで2種類のPoP検証が必要になる。既存の資産（mTLS、custom plugin）を活かせない |
| 3rd PartyのRouteを`tls_client_auth`だけに絞る | 構成は小さくなるが、client認証方式を比較するというデモの価値が失われる |
