# ADR 0021案: WP5のrevocation metadata差分を記録して現構成を維持する

- Status: Proposed（metadata差分の受容は未承認）
- Date: 2026-10-05
- 関連: ADR0011、ADR0012、WP5 META-02

## 確認した事実

通常DPからCA/SANを検証し、metadata cert付きで内部discoveryを取得した。issuer、authorization/end-session、token/PAR/JWKSとtoken/PAR aliasは静的設定に一致する。revocationだけは以下のとおり異なる。

| 対象 | URL |
|---|---|
| discovery revocation_endpointとmTLS alias | https://localhost:8444/realms/fapi-demo/protocol/openid-connect/revoke |
| transportと両OIDCの静的revocation/mtls_revocation設定 | https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/revoke |

固定Keycloak 26.7.4は[revocation URLをfrontend URIで生成](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/OIDCWellKnownProvider.java#L206)し、[同じ値をmTLS aliasへコピー](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/OIDCWellKnownProvider.java#L342)する。token/PAR/JWKSとは生成元が異なり、back-channel dynamic設定でもこの差分が生じる。

現構成の内部revokeは同じKeycloakの同じrealm/pathへ接続する。実AS observer付きの直結v2/v6でRoute別mTLSとrevokeを確認済みで、通常A/Bのstock logoutも成功している。HTTP200/logout成功は個別token失効SLAの保証とは区別する。

## 提案

静的内部URLとmTLS transportを維持する。META-02の文字列完全一致は未達として既知差分を記録し、この差分をデモ受入の阻害条件から除外する。通知と設定が一致したとは主張しない。Keycloak providerや通知URLを書き換える追加実装を作らない。

目的は受け取った要件をKong標準優先で実装して実演すること。API binding、ASへのmTLS、PKJWTと正常logoutの実証は維持する。FAPI完全準拠の認定には使わない。今回の提案は実行時のendpoint・origin許可範囲を広げず、runtimeの設定変更も伴わない。

## 受入への影響

重い網羅検証の省略は利用者が2026-10-05に承認済み。代表redirect負例もpassした。このADR案で未決なのはrevocation通知URL差分の受容だけである。承認後もmetadata全項目完全一致をpassにせず、証跡と差分を残す。公開image/clean checkout再現はWP6で扱う。
