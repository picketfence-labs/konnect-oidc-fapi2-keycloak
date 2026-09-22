# ADR-0002: Konnect から data plane ライセンスを継承する

- 日付: 2026-09-16
- 状態: 決定済み

## 背景

ローカルの Kong Gateway は Konnect 管理の control plane に接続する data plane として動きます。接続した data plane は組織の Enterprise ライセンスを Konnect から継承します。

## 決定

ローカル環境や Docker Compose に `KONG_LICENSE_DATA` を設定しません。別のライセンスを持ち込むと管理先が二重になり、追加の期限付き secret が必要になります。

## 影響

- data plane が意図した control plane に接続していることを確認する。
- OIDC と Route By Header の利用可否は Konnect 組織の権利に依存する。
- 起動と E2E 検証時に、data plane ログで接続とライセンスのエラーを確認する。
- 独立した control plane を使う場合はライセンス方針を決め直す。

## 参考資料

- https://developer.konghq.com/konnect/
- https://developer.konghq.com/gateway/entities/license/
