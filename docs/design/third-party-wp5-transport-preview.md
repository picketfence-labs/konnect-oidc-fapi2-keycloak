# WP5 5c Gateway–AS直結検証

## 現在の実行範囲

Kong標準優先の顧客要件デモとして、専用の隔離環境でRoute A/BのAS通信を確認する。本番FAPI完全準拠は対象外。stock PAR/revoke本文は変更せず、PARのclient_id欠落はRFC 9126の既知gapとして記録する。

実行元は`tests/harness/wp5_observer/transport_fixture.py`。5a受入済みのobserver image・証明書生成・コマンド制限・秘密値scanを再利用する。通常環境、Control Plane、既存realmを変更しない。

- 専用project: `wp5-as-peer-transport-v2`。Kongとobserver Keycloakの2サービス、専用networkとH2 volume。
- host fixture: `/private/tmp/wp5-as-peer-transport-20261004-v2`。directory0700/file0600、read-only mount。
- host公開: loopback8443/8444のみ。KongからASへ`https://keycloak:8443`で直接接続し、relayを使わない。
- cached imageをIDで固定し、build/pullを行わない。上限3CPU/7GiB、startup180秒、run720秒、cleanup120秒。
- marker前: A/Bとも503、AS observer行0。ready workerのgeneration/config/epochを確認した後にlocal markerを配置する。
- marker後: A/BのPAR→実user login→code→session→refresh→stock logout→access/refresh revokeを実行する。
- ASの各operationと診断行を1:1照合し、Route別peer・専用metadata peer・PKIX/期限/clientAuth EKU・token cnf一致を確認する。
- raw token/JWT/jti/body/cookie/password/license/PEM/logは公開せず、固定status・claim判定・相関ID・公開leaf digestだけを記録する。
- 終了時は所有権を確認した専用resourcesだけを回収し、port releaseとprivate fixture削除を独立確認する。

## 検証層の区別

transport/bridge unitとnative PS256/X509 probeはPASS。通常stateのvalidation、既存test suite、起動gate/selectorのoffline checksもPASS。これらをAS直結やexact runtime lifecycleの成功に読み替えない。今回の二サービスfixtureはAS側の通信を確認し、API Gateway/Upstreamまでの通常統合・未実行negative・main上での受入は別に記録する。Issue #11は自動closeしない。

## 実行結果（2026-10-04）

| 試験 | 結果 | 確認した範囲 |
|---|---|---|
| 直結 v1 | failed、回収済み | NGINXの環境変数設定に余分な`env`があり起動停止。ASフローは未実行 |
| 直結 v2 | accepted、44.564秒 | A/B各PAR201、code/refresh200、callback302、session cookie更新、保護GET200、stock logout、access/refresh両revoke200 |
| 拡張 v6 | accepted、43.869秒 | A/Bともissuer不一致401→正規callback302、2回のrefresh、rotation利用、PAR query/nonce/S256/callback判定。実AS15件join |
| guard v3 | accepted、45.681秒 | 2 worker、assertion偽装3種400、marker欠落/config不一致/再起動/古いepochでA/B503、AS送信0 |
| 通常起動preflight | pass、5ケース | 固定image内で両pluginありの対照と、両方/bridge/handler欠落時の停止。networkなし、実entrypointはsentinelへ置換 |

v2は13 operationを実AS observerへ1:1照合した。A/Bの各5認証操作とmetadataのdiscovery2/JWKS1を含む。Route別の実peer、専用metadata peer、PKIX・期限・clientAuth EKU・leaf一致、code/refreshの4応答すべての`cnf`一致を確認した。Route Bの全5認証操作でPS256、issuer文字列aud、iss/sub、TTL60秒以内、異なるjtiを確認した。

v3は別の専用project `wp5-as-peer-transport-v3`を使い、成功済みのloginフローを再実行していない。2 workerのPIDとregistry epochがreloadで変わり、旧markerを再配置しても503になることを確認した。header/query/bodyのassertion偽装は400。全試験を通じAS observer・送信診断行は0件だった。

v2/v3/v6とも秘密値検出0。専用container/network/volume、loopback8443/8444、private fixtureの回収をRootが独立確認した。通常環境、Control Plane、通常realmは変更していない。

| 証跡 | terminal receipt SHA-256 | Root独立確認（Git外） |
|---|---|---|
| 直結 v2 | `5283c0740b1dbe02ab64df02af3b997c326d51d348860ecf55131025f4931cb9` | `.generated/evidence/wp5-root-transport-v2-terminal-review-1791106088625503000.json` |
| 拡張 v6 | `9b628ed21e550432405697ee7ac4281fb3b98936c0a087120774ec9ec3424ebd` | `.generated/evidence/wp5-root-transport-v6-terminal-review-1791108590659333000.json` |
| guard v3 | `86cafd4edd712b4df047522355763e3f8c9e47d2748be9b4462ce865e9326a97` | `.generated/evidence/wp5-root-transport-v3-terminal-review-1791106594216671000.json` |
| 起動preflight | — | `.generated/evidence/wp5-root-native-startup-guards-1791106787009061000.json` |

### 拡張試験の補正履歴

v4はharnessの400固定判定で停止、v5は残っていた重複判定で停止した。v5のRoute Aは実際にはissuer不一致401拒否と、その後の認可・2 refresh・logoutまで成功した。成功へreceiptを書き換えず、別v6でA/B全体を確認した。拒否は400/401を許可し、正規callbackの成功とcode交換各1回を必須とする。harnessの失敗時は固定outcome/status/countだけを記録する。stockの本文・認証・iss欠落方針は変えていない。

v4 receipt SHA-256: `69730c4b856c08413eeef8ef07137e9018dbf69b0ffa83d325472f043b791d88`。v5: `3eafd94ac56afffec11bbfd9fafb508227fd0e847f12bb47a4ac4a9bd1e1168d`。両方の専用resource/port/private fixtureをRootが独立確認した。

v6の2回目refreshは最初の更新tokenを使用し、さらに異なる更新tokenを受け取った。比較に使ったhashはfixture-onlyのworker共有辞書内で120秒だけ保持し、公開はbooleanだけとした。PKCEのS256/challenge存在は確認したが、複数の認可開始間のchallenge freshness比較は今回のreceiptに含まない。

## 通常Control Planeの読み取り専用preview

`make deck-diff GATEWAY=third-party STAGE=runtime`は成功。対象third-party CPの両custom schema hashがrepositoryと一致した。差分は**create11 / update0 / delete0**（Service2、Route2、service plugin7）。foundation certificate/CA/global transportは変更されない。API CPにはアクセスしていない。

- state SHA-256: `36fc03c08294f3880153078c0c50fc7e51e22a1a19e376f2384ba462e2653cf1`
- private role inputのcanonical SHA-256: `7e2b1d255168043bf8717f61378a80b4af550ca6472f360e123dccad5592c88f`
- `sync`は引き続き無効。API側WP3 migration（既存preview create6/update0/delete13）と合わせた通常環境のレビュー・適用は未実施。

## 残る受入

[受入対応表](third-party-wp5-acceptance.md)を正本とする。二サービスAS直結はAPI Gateway/Upstreamの統合、通常supervisorの公開・閉鎖、個別token失効、未実行のstock負例の証明ではない。PRの独立レビュー、利用者によるmerge、mainでの通常統合検証と受入が残る。
