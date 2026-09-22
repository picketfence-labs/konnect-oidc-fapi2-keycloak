# ADR-0003: OIDC 検証に Gateway 3.16 を使用する

- 日付: 2026-09-22
- 状態: 決定済み

## 背景

Gateway 3.15.0.5 のブラウザーログインは Auth0 認証後の callback で 401 になりました。`client_secret_post` から `client_secret_basic` への変更では解決しませんでした。3.14.0.14 への一時的な変更も準備しましたが、ブラウザーでの再検証結果は残っていませんでした。3.16.0.0 は Konnect に対応し、OIDC の token endpoint 認証に関する修正を含みます。ただし、今回の 401 がその修正対象だったとは断定できません。

## 決定

Konnect 接続のローカル data plane に `kong/kong-gateway:3.16.0.0` を使用します。Auth0 と Kong の `client_secret_basic` を揃え、構成やライセンス方式は変えません。

## 検証結果と影響

当初、3.16 でも 401 が続きました。主因は Auth0 Management API の読み取り scope 不足で、OIDC plugin に client secret が渡っていなかったことです。scope と secret を修正した後、ID token の HS256 署名も RS256 に変更してブラウザーログインが通りました。engineering と sales の結果を確認しています。`client_secret_post` の再検討は次の要件確認まで保留です。3.14 と独立ライセンス方式は現在の作業対象ではありません。

## 参考資料

- https://developer.konghq.com/konnect-platform/compatibility/
- https://developer.konghq.com/plugins/openid-connect/changelog/
