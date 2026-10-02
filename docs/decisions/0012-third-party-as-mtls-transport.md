# ADR 0012: AS mTLS transportを専用custom pluginへ分離する

- Status: Accepted（設計PR #5、2026-10-02 merge。DP0の設計契約でありruntime未受入）
- Date: 2026-10-02
- Implements: [ADR 0011](0011-customer-demo-scope.md)のP0
- Contract: [AS mTLS補完契約](../design/third-party-as-mtls-transport.md)

## Context

3rd PartyからASへの実際のback-channel requestをすべてmTLSにする。単にOIDC設定へcert IDを置くだけでは足りない。cached Kong 3.16.0.0 imageの変更していないbytecodeを、HTTP/暗号処理をmockしたhost LuaJITで実行すると、PKJWTを選んだPAR/revokeにはTLS client certが渡らず、discovery loaderもcert optionを転送しなかった。低水準JWKS loaderはcert optionを受け取れるが、pluginのmetadata取得経路がそれを供給する保証にはならない。

既存bridgeのheader注入はtoken/refresh専用であり、Route A、共有metadata cache、background取得を補完できない。また、stock token/refreshのPKJWTはtoken endpointをaudience引数にするため、本デモのissuer文字列audienceには既存bridgeの署名処理が必要である。

## Decision

1. 3rd Party Gatewayだけに、global custom plugin **`fapi-as-mtls-transport`**を追加する。workerで一度だけ公開HTTP API `resty.http.request_uri`をdecorateし、明示inventoryのAS requestにcert/keyを付ける。private OIDC module/fileの差し替えはしない。ただしworker-wideのruntime method decoratorであり、stock機能や公式推奨拡張点とは説明しない。
2. certは認証POSTにRoute A/Bのcert、discovery/JWKSとbridge独自discoveryに専用**3rd Party metadata cert**を使う。共有cache・background/light-thread取得をRouteの実行順に依存させない。
3. Route BのPAR/revokeはstock PKJWT生成を残す。token/refreshはstock TLS branchを残し、bridgeの署名処理を送信境界で呼ぶdelegate interfaceへ限定変更する。accessで作ったJWTをheader経由で使い回さない。transport plugin自体は署名鍵を持たない。
4. issuerと内部discovery URLの対応は固定mappingとする。取得先の変更はissuer文字列の変更ではない。認証POSTはdiscoveryの通常endpoint/mTLS aliasを明示設定し、動的なURL選択、redirect追従、server-only HTTPSへのfallbackを認めない。
5. デモではkeepalive/TLS session reuseを無効にする。同じ認証POSTの自動再送を禁止し、送信結果が不明ならfail closedとする。新たな利用者操作で新しい認可フローを開始する。設定・鍵変更はrestartで反映し、hot rotationを作り込まない。
6. 方式選択をWorkerへ戻さない。DP0の設計成果は本ADRと契約に固定する。独立レビュー・設計merge後にWP5をreadyにできるが、実際のTLS、Keycloak受入、plugin lifecycle、drift検出はWP5の必須受入である。先頭spike AS-MTLS-OBS-01で[test-only Keycloak peer observer](../design/third-party-as-peer-evidence.md)・ID相関・stock assertion claimの成立を確認し、不成立なら本体実装前に戻す。pluginのロードとentity有効化を区別してGateway別に必須/禁止を設定する。成立しなければDesign ownerへ戻す。

## Alternatives

- **既存bridgeだけの拡張**: Route B access hookだけではRoute A/共有metadata/background取得を覆えないため不採用。
- **pre/post functionによるheader追加だけ**: 内部HTTP requestのTLS certとPAR/revokeを制御できないため不採用。
- **別BFF/sidecar AS proxy**: request ownershipや追加TLS終端・鍵管理が増える。今回の固定版デモでは追加containerなしの方法を採用する。選択方式がruntimeで成立しない場合の再設計候補には残す。

## Consequences

- PKJWT生成、mTLS transport、token bindingを別責務として説明できる。metadata certはOAuth client認証やtoken bindingに使わない。
- method decoratorの影響範囲、startup/configure/無効化、並行request、retry、秘密情報非漏洩をテストする必要がある。本番向け拡張やupgrade互換性を保証しない。
- オフラインprobeは42件passだが、実TLS、実署名、Keycloak、Kong lifecycleをmockしている。**デモ動作済みでも、WP5受入済みでもない。** private bytecode・disassembly・秘密情報は公開成果へ含めない。
- Keycloakは引き続き`request`モードであり、ASのcertなし接続を入口で一律拒否する構成ではない。
