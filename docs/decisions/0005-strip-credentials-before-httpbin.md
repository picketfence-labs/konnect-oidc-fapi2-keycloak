# ADR-0005: httpbin へ送る前に認証情報を削除する

- 日付: 2026-09-22
- 状態: 実装済み

## 背景

最初の E2E 応答では、httpbin が `Authorization` の access token と `Cookie` の localhost cookie を返しました。UI も応答全体を表示したため、認証情報が画面に出てレイアウトが崩れました。UI をルーティング証跡だけの表示に変えても、backend への送信は止まりません。

## 決定

デモ Service に Request Transformer を追加し、Upstream へ送る前に `Authorization` と `Cookie` を削除します。priority 801 なので、OIDC（1050）による認証と Route By Header（850）による選択の後に動きます。デモで使用する 2 つの claim ヘッダーは残します。

## 検証と影響

通常版と PAR 版の decK 設定に同じ plugin を追加しました。同期後の diff は 0/0/0 で、ブラウザーからの新しいリクエストでは httpbin に認証情報が届かず、ルーティングヘッダーだけが届きました。将来 backend が bearer token や cookie を必要とする場合は、その要件を定義してから規則を見直します。
