# リポジトリの作業規則

構成を変更する前に `docs/design-brief.md` を読んでください。継続して参照する設計判断は
`docs/decisions/` に、予期しない失敗は `docs/troubleshooting-log.md` に記録してください。

## コマンド

- 整形と検証: `make validate`
- 外部変更のプレビュー: `make plan` と `make deck-diff`
- 人がプレビューを確認した後の適用: `make apply`、`make deck-sync`、`make up`
- 削除: `make destroy`

`.env`、`.generated/`、Terraform state、証明書、パスワード、Auth0 の secret、
Konnect token、Kong ライセンスを commit しないでください。`terraform apply`、
`terraform destroy`、`deck gateway sync`、Docker の変更には利用者の明示的な意図が必要です。
人間のレビュー担当者に代わって Pull Request を merge しないでください。
