# ADR 0011: 完全適合ではなく顧客必須要件を示す動作デモを作る

- Status: Accepted（設計PR #5、2026-10-02 merge。runtime未受入）
- Date: 2026-10-02
- Amends: [ADR 0009](0009-third-party-client-gateway-topology.md)、[ADR 0010](0010-api-gateway-resource-server-validation.md)。[ADR 0008](0008-route-b-endpoint-auth-split.md)のendpoint分担は、v1の記録として保持し、3rd Party構成では変更する。

## Context

利用者が目的を明確化した。お客様はFAPI 2.0の検討段階であり、完全適合や本番運用可能な環境を求めていない。mTLSは必須、private_key_jwtは必要、DPoPは対応できるとベターである。前回デモは好評だったが、3rd Partyがなく、3rd Partyとの通信がmTLSになることを示せていなかった。

以前の設計は、完全適合に向けた追加guardや厳密な失効検証をデモの完了条件へ持ち込みすぎていた。一方、Route BのPAR/revokeをserver認証HTTPSへ下げた修正は、今回の接続方針には合わない。

## Decision

1. 完成条件は、3rd Partyを含む両Routeを実際に動かし、顧客必須のmTLS・PKJWTを証跡で説明できることとする。完全適合、OIDF認定、本番運用可能性は主張しない。
2. mTLS対象は3rd PartyからAS・APIへのサーバー間通信とする。PAR/token/refresh/revokeだけでなく、stock/bridgeのdiscovery・JWKS、実行時に追加で発生するAS back-channelも対象とする。browserのlogin/redirect/logoutと管理経路は別扱いとする。
3. Route BのOAuth client認証はPKJWTのまま維持する。ASのPAR/revokeにもmTLS transportを補完する。既存bridgeの単純移設では達成できないため、Design ownerのDP0でexact imageのオフライン技術確認と補完契約を確定し、runtime確認はWP5の必須受入としてWorkerへ渡す。P0を標準pluginだけに限定しない。
4. Keycloakの共有browser listenerはclient certを任意要求する`request`モードを維持する。提示certの検証と、実際のサーバー間requestのmTLSを示す。全AS入口でcertなしを拒否するlistenerではないことを開示する。API Gatewayではcert欠落・binding不一致を拒否する。
5. PAR、PKCE S256、token有効性、issuer/audience/scope、header限定、refresh等は標準機能の追加価値として採用し、必要性を説明する。新たなcustomが必要ならDesign ownerへ戻して範囲を再提案する。
6. 開始CSRFの追加防御、iss欠落guardは完全適合へ向けた将来対応として開示する。今回の開発ゲートから除外するが、安全性の保証や仕様適合の認定にはしない。提示されたissの不一致検査、state/PKCEは維持する。
7. logout/resetは次のデモケースを実行できるための機能とする。stock logout/revokeを使用し、必要なら対象demo userに限定した文書化済みの手動resetを許容する。個別token失効・30秒の反映SLA・専用失効pluginは要求しない。
8. API Gatewayのintrospection + mTLS PoPを推奨構成として維持する。JWT検証だけを失効確認と同一視しない。成立しない場合の代替はDesign ownerがデモ要件と本来要件への影響を整理して設計を改訂する。Workerの暗黙downgradeは認めない。
9. DPoPは追加候補としてDesign ownerがDP1を行う。RS側の標準検証と、client側のproof生成・nonce対応を分けて可否/工数を提案する。必須mTLS経路の置換やDPoP実装着手は行わない。

## Consequences

- FAPIの仕様要件、顧客必須、標準機能の追加価値、デモ運用、将来対応を別々に説明できる。
- AS全back-channel mTLSの方式は[ADR 0012](0012-third-party-as-mtls-transport.md)とDP0契約へ固定した（設計PR #5、merge済み）。WP5の開始には依存WPの受入が必要。実装可否が未確認の方法を「対応済み」と表現しない。
- strictな失効/CSRF/iss欠落シナリオは将来・任意に分類する。P0のmTLS/PKJWT、token有効性/PoP、資格情報非漏洩の失敗は、引き続き完了阻害条件である。
- この決定はmain上の設計として合意済み。実装やlive環境の変更を意味しない。

## References

- [デモ対応範囲と追加実装](../design/third-party-demo-explainer.md)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html): mTLS transport、client認証、sender constraintは別の役割。
- [Keycloak 26.7.4 mutual TLS設定](https://github.com/keycloak/keycloak/blob/26.7.4/docs/guides/server/mutual-tls.adoc): request/requiredの違い。
