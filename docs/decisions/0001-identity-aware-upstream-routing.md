# ADR-0001: access フェーズでの Upstream 選択

- 日付: 2026-09-15
- 状態: 決定済み

## 背景

認証済みの `department` claim は OIDC plugin の実行後に得られます。Kong の基本ルーターはそれより先に Route を選ぶため、同じリクエスト中に OIDC が作ったヘッダーを別の Route の条件にはできません。

## 検討した方法

1. 基本ルーターの expression Route: 認証後のヘッダーを参照できない。
2. 2 回目のリクエストへリダイレクト: 構成が複雑になり、ヘッダー偽装やセッション対応付けの懸念が増える。
3. Route By Header: OIDC の後に保護されたヘッダーを使って Upstream を変更できる。
4. DataKit: より複雑な claim 変換には適するが、この 2 つの完全一致には大きすぎる。

## 決定

Auth0 Action が部門とルートの claim を作り、OIDC `upstream_headers` が `X-Demo-Department` と `X-Demo-Route` を上書きします。Route By Header が両者の組で Upstream を選びます。3 つの Upstream は同じ httpbin Target を参照し、Gateway Service と Route は各 1 つにします。

## 影響と検証

- UI では「論理ルート」または「選択された Upstream」と表記する。
- `X-Demo-Route` は署名済みユーザー情報に由来する判定用ラベルで、Route By Header が出力する値ではない。
- 条件が増えたり外部参照が必要になったりした場合は DataKit を再検討する。
- OIDC と Route By Header は Enterprise plugin で、data plane は Konnect からライセンスを継承する。
- Gateway 3.16 の実ブラウザーで engineering と sales のルーティングを確認した。engineering では偽装したヘッダーも認証済みの値に置き換わった。sales の結果は利用者による報告。
