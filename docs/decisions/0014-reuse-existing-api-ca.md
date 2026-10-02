# ADR 0014: API foundationは既存CAを変更せず再利用する

- Status: Proposed（承認済みsyncで判明した制約への修正。実装PRのレビュー・利用者merge後にmainで再検証する）
- Date: 2026-10-02
- Amends: [ADR 0013](0013-work-package-schema-and-acceptance-boundaries.md)のAPI foundation CA所有範囲
- Preserves: 既存v1のupdate/delete=0、用途別の鍵分離、P0、stage/tag限定、runtime受入と環境承認の境界

## 問題と実証

main `ccd0d3c`のfoundation previewはAPI create3、third-party create4、update/delete=0だった。利用者の承認後、APIのintrospection/upstream Certificate 2件は作成されたが、CA `77777777-7777-4777-8777-777777777777`はHTTP409 `unique-certificate-per-entity`で拒否された。read-only diffでは、同じCAを異なるIDで登録する際の一意制約を検出できなかった。

API CPにはv1 CA `33333333-3333-4333-8333-333333333333`が既にあり、tagsは`[fapi2-demo]`。公開証明書のDERはrole入力の開発CAと一致する。[Kongの公開CA schema](https://github.com/Kong/kong/blob/master/kong/db/schema/entities/ca_certificates.lua)にも証明書digestのunique指定がある。これは公開sourceによる補強であり、exact Enterprise版の実装確認ではない。今回の制約は対象Konnect CPの409応答と既存CAの読み取り照合で確認した。

承認済みのthird-party側4件は作成され、設定照合とpost-sync diff=0に成功した。APIの残差は上記CA create1だけ。sync前に取得した両CPの既存Service、Route、Plugin、Certificate、CAのID集合・canonical hashは、適用後も不変だった。raw API body、証明書、秘密値は公開しない。

## 決定案

1. API foundationはintrospection Certificate `44444444-4444-4444-8444-444444444444`とupstream Certificate `55555555-5555-4555-8555-555555555555`だけを管理する。両entityのタグ、公開証明書のrole入力、env Vault key参照は維持する。CA `77777777-7777-4777-8777-777777777777`は宣言しない。
2. APIの既存CA `33333333-3333-4333-8333-333333333333`を、WP1が変更しない外部前提として検証する。foundation stateへ含めず、foundationタグ追加・更新・削除・別ID検索・自動createを行わない。
3. API foundationのdiff/syncは、local scope検証とlive CP metadata照合後、decK起動前に既存CAを固定IDでGETする。ID、tags=`[fapi2-demo]`（順序不問）、公開CA DERとrole入力の一致を要求する。欠落、HTTPエラー、不正応答、タグ違い、証明書不一致、不正PEMは非zeroで停止する。値や応答bodyをログへ出さない。
4. third-partyは別CPであるため、同じCAの`33333333-3333-4333-8333-333333333333`を従来どおりfoundation entityとして管理する。両CPでの同じIDは同じ所有範囲を意味しない。
5. WP3のAPI runtimeはfoundationの2 Certificateを同一ID・タグで包含し、既存CA `33333333-3333-4333-8333-333333333333`を`[fapi2-demo]`のまま宣言・参照する。v1 migrationでもCAを削除・再作成しない。runtime migration previewと承認は別に行う。
6. この修正はCAの作成を取り消す宣言変更とread-only検査であり、新たなlive mutationを行わない。main反映後は両foundation diff=0、CA前提照合、既存entity不変を独立検証してWP1 Technical Completion Reportを更新する。Issue closeと後続WP開始には利用者の受入が必要。

## 選ばなかった方法

既存CAへfoundationタグを付け足すとWP1の既存update=0を破る。別CA生成では現在のRoute証明書のtrustが変わり、鍵・leaf再発行とrealm/runtime変更が必要になる。既存CAの削除・再作成もv1を保全できない。いずれも今回の7件create承認の範囲に含めない。

## 受入条件

- API foundationのCA混入、タグ・固定ID・key参照の改変をlocalで拒否する。third-partyの4 entity契約は維持する。
- 既存CA照合の正常系と欠落／ID／タグ／DER不一致／不正PEM／HTTP・応答不正を検証する。失敗時にdecKが呼ばれないことを確認する。
- `make validate`、`make test`、`make test-plugin`と差分検査が成功し、schema pagination、scope拒否、秘密非出力の回帰がない。
- main反映後の両live foundation diffはcreate/update/delete=0。共有CAは変更されず、runtime/Docker/realmは未実施のまま。
