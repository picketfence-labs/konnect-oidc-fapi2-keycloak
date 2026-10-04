# ADR 0019: stock PAR/revoke spikeのidentityと段階ゲート

- 状態: 設計採用、5a受入済み。後続5b/5cの隔離結果は[WP5受入表](../design/third-party-wp5-acceptance.md)を参照
- 日付: 2026-10-04
- 対象: WP5 5a、OMD-02の公開OIDC経路による実署名claim確認

## 背景

OMD-02は既存bridgeのheader modeを使うv1相当のstock生成spikeである。`kong/kong.yaml`のRoute Bは`kong-fapi-pkj-mtls`、third-party foundation/realm templateは`third-party-fapi-pkj-mtls`を使うため、両方を参照するとfixtureのidentityが不一致になる。また、新transportを使わない既存bridge/stockのAS要求には相関IDがなく、metadataやtokenのobserver行をPAR/revokeの一次証跡と同じ基準で判定できない。

## 決定

spikeの基準を`kong/kong.yaml`の`kong-fapi-pkj-mtls`とし、専用realm client、bridge、OIDC、署名のiss/sub、Route B証明書を一貫して固定する。専用PKIと署名鍵を生成してfixtureに登録し、通常realm/template、foundation、Control Planeを変更しない。third-party clientの統合は5b/5cに残す。

最初のfresh認可開始でstock PARを1回採取し、実署名、PS256、issuer文字列aud、`0 < exp-iat <= 60`、残存TTL >= 5秒を最初に検査する。不適合ならform/assertionを修正せず、後続session/logoutを実行せずにneeds-designとcleanupを記録する。通過時だけ実ASへ無変更でforwardし、実PAR応答を使う認可・code exchange・session・2種類のlogout revokeへ進む。

PARと各revokeは最終AS送信で別相関IDを生成し、stock claimと実AS observer行を1:1でjoinする。相関IDなしの補助要求は、予測したendpoint/methodの`correlation_invalid`行だけを有限件数で別集計する。その他のerrorや予測外行、対象PAR/revokeの欠落・重複・不一致はfailとする。`correlation_invalid`はpeer確認前の結果なので、補助要求の証明書有無・mTLS成功を主張しない。metadata/stock直結transportの受入は後続gateに残す。

TLS relayは、このリポジトリで使ったキャッシュ済みPython検証imageの専用commandから実行する方式を優先する。image identity、実crypto依存、public harness、mount、network、loopback入口、所有リソース、cleanupを具体的previewで確認する。通常verifierアプリは起動せず、image取得・追加relay image buildを前提にしない。

## 隔離fixtureのnetwork（2026-10-04追記）

stockと再入計測には、受入済みdirect TLS v3と同じ専用bridgeを使う。このDocker環境の小さいHTTP対照試験では、`internal:true`でhost loopbackからの到達が失敗し、通常bridgeで成功した。証跡は`.generated/evidence/wp5-root-loopback-topology-control-1791091960731873000.json`。再入r3はこの到達確認で停止し、PARは未送信だった。

専用project・所有label・loopback限定publish・固定image・read-onlyの専用PKI・実行上限・cleanupは維持する。通常networkやControl Planeを変更せず、追加の外部サービスへ接続しない。stockのAS要求先は既定のI/Hと内部Keycloakに固定し、Kongのanonymous reportsを無効にする。networkの補正はclaim、issuer、TLS peer、observer契約の変更に数えない。

## 結果の限界

このfixtureはstock生成claimとrelayから実ASへのTLS peerを検査する。stockから実ASへの直結mTLS、third-party統合、revokeによる個別token失効、WP5全体の完成を証明しない。実行receiptとRootの独立確認が揃うまで各項目は未受入とする。

## v5で判明したPAR契約の相違とデモ範囲の決定

v5の実認可開始はHTTP500となり、relayは`par_client_id`で署名検証前に拒否した。`relay_attempted=false`、`forwarded=false`でASへのPARは未送信。receiptだけではフォーム項目の欠落と値の不一致を区別できない。一方、固定版Kong 3.16のcached SDKの読み取り専用分析では、`private_key_jwt`分岐がフォームの`client_id`を除去し、そのままPAR本文をencodeすることを確認した。同じ署名方式のままIDを保持する公開設定は見つからなかった。他の認証方式への切替はOMD-02のPKJWT条件を満たさない。

[RFC 9126 §2.1](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1)は、PARにも`client_id`を必須としている。固定Keycloak 26.7.4の[JWTClientAuthenticator](https://github.com/keycloak/keycloak/blob/aa9fe3fba0c6cd5770f19a49378c55f4378cf544/services/src/main/java/org/keycloak/authentication/authenticators/client/JWTClientAuthenticator.java)にはassertionの`sub`からclientを解決する処理があるが、それだけではPARの仕様適合や実AS成功を証明しない。欠落を黙って許容してstock PARを受け入れることはしない。

Rootの独立監査は`.generated/evidence/wp5-root-stock-v5-terminal-review-1791093611939675000.json`。terminal receiptは`/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v5.json`、SHA-256 `7c2d9f71fde9d626e7e04a209f70c0f0f3b8256f5543ff36f64584a51a1c06ce`。input hash、旧receipt不変、専用container/volume/networkの消滅、3ポート解放、private fixture回収を確認した。stage 2は未実行。署名・aud・TTLは未検証で、WP5受入は未完了。

### 利用者の決定（2026-10-04）

目的は、受け取った顧客要件をなるべくKong標準機能で実装し、その環境をデモすることである。本番運用に向けたFAPI 2.0完全準拠環境の構築は目標にしない。利用者はstockの現状維持を指定し、フォームID欠落の仕様差分は記録にとどめると明示した。先に提示したclient_id補完案は採用しない。補完コードや本文変更は実装していない。

検証harnessは、PARのclient_idが欠落している場合も実署名のiss/subから固定clientを照合する。明示されたIDの不一致・重複は拒否する。受信した本文・assertionをbyte-for-byteそのまま実Keycloakへ1回送信し、ID追加・再encode・再署名は行わない。既存のPS256、issuer文字列aud、TTL、jti一回限り、CA/SAN、Route B cert、実AS応答・peer joinを維持する。ASが拒否する場合は事実を記録し、成功へ偽装しない。

FAPI 2.0 Security Profile §5.3.3.2のPAR要件はRFC9126を参照するため、stockのform client_id欠落は適合上の既知gapとして開示する。デモの動作検証成功とFAPI準拠は別に記録し、このgap自体をデモ完成の阻害条件にしない。gapの根拠・証拠・デモ上の扱いは[要件対応表](../design/third-party-fapi2-conformance.md#既知のparギャップ2026-10-04)へ記録する。stockへの修正、対応version探し、vendorへの問い合わせは今回の作業に追加しない。

次は、このabsent-only許容を最小修正として確認し、fresh v6 fixtureで実PARの署名とKeycloak到達を検証する。通過後は通常の認可・code交換・session・stock logoutを確認し、顧客必須のPKJWTとmTLSのデモ実装へ進む。開発担当はLuna / xHighを維持する。

### v7の実測と次の最小修正

v7でstockのform client_id欠落を実測した。元本文を無変更で転送し、実PS256・issuer文字列aud・固定iss/sub・TTL60秒・残存TTL60秒を確認した。実Keycloakは401/invalid_requestを返したが、PARの相関IDとRoute B peerの1:1対応、chain2・PKIX・有効性・clientAuth EKUは通過した。これは署名と実mTLS到達の証拠で、PAR成功やsession完成ではない。Root監査は`.generated/evidence/wp5-root-stock-v7-terminal-review-1791096012489613000.json`、terminal SHA-256 `d8215f38fe5b167faf2fa1e7cbc3b6f2ff6bf51532700bb138452135032ce8f1`。専用リソース・PKI・3ポートは回収済み。

公開Keycloakコードでは、`CertificateInfoHelper`が`jwt.credential.kid`を読み、`ClientPublicKeyLoader`は欠落時にpublic keyからIDを生成する。fixtureはstock JWKに別のIDを設定していたが、realmには公開鍵だけを登録していた。この設定不一致を補正し、同じkidを登録する。401 receiptは内部例外を保持していないため、原因の確定は再検証で行う。stock本文・認証方式・TLS検証は変更しない。

次のfresh v8では、実PAR201と署名検査を通過した場合だけ、同じ試行のmemory内Location/cookieを使って通常ログイン・code交換・session・stock logoutへ進む。専用realm user以外の登録・既存user変更は行わない。logoutの実access/refresh revokeを確認するが、個別失効保証や反映SLAを追加条件にしない。v8の111件のfocused testsをRootが独立実行してPASS。

### v8: PAR受入、session/logoutは未受入

鍵ID登録を合わせたv8では、stockの本文を変更せず実PAR201となった。PS256、issuer文字列aud、固定iss/sub、TTL60秒、実ASのRoute B peerとの1:1 joinをRootが受け入れた。ログイン後のKong callbackは4xxで、sessionとlogout revokeは未完成。callbackの固定error enumで原因を絞り、通常のfixture修正を続ける。Root証跡は`.generated/evidence/wp5-root-stock-v8-terminal-review-1791097316821119000.json`、terminal SHA-256 `55eb4f7ce02b5c15bba63c57ff0d40b8b3ba77cb0aca602c050c43b6e6550000`。ログの秘密値検出0、専用環境・PKI・3ポートは回収済み。PARのRFC 9126ギャップは機能成功とは別に記録を維持する。


### v15: stock claim、session/logoutの受入

2026-10-04: WP5の5aはRoot受入済み。direct TLS v3（40/40）、同一要求の再入r4、stock v15のPAR201・token200・callback302・session成立・logout・access/refresh両revoke200を確認した。stock3操作はPS256・issuer文字列aud・TTL60秒・異なるjtiを満たし、実ASのRoute B peerと1:1対応（chain2/PKIX/期限/EKU/leaf一致）。秘密値検出0、専用Docker環境・PKI・3ポートの回収を独立確認した。Root証跡は`.generated/evidence/wp5-root-stock-v15-terminal-review-1791101147900716000.json`、v15 receipt SHA-256は`f0348037bf6796be694f9a00d58bcfeea0b963b8547f16bc5383a4c8b4257519`。Luna / xHighによる5b transport/bridge本体と5cの設定・起動ゲートの実装へ進む。PARのRFC 9126ギャップは開示のみ。5aのrelayからASへの証明を、まだ未検証のGateway直結transportや個別token失効の証明には扱わない。
