# DP0: 3rd Party → ASのmTLS補完契約

> 2026-10-04現在の実装・検証結果は[WP5受入表](third-party-wp5-acceptance.md)を参照。5a受入、5b実装、5c隔離AS直結・2 worker guardは通過した。通常環境での受入は未完了。以下の契約や過去の試行記録から、現在の成功・未実行範囲を推定しない。

## 状態と境界

2026-10-04: WP5の5aはRoot受入済み。direct TLS v3（40/40）、同一要求の再入r4、stock v15のPAR201・token200・callback302・session成立・logout・access/refresh両revoke200を確認した。stock3操作はPS256・issuer文字列aud・TTL60秒・異なるjtiを満たし、実ASのRoute B peerと1:1対応（chain2/PKIX/期限/EKU/leaf一致）。秘密値検出0、専用Docker環境・PKI・3ポートの回収を独立確認した。Root証跡は`.generated/evidence/wp5-root-stock-v15-terminal-review-1791101147900716000.json`、v15 receipt SHA-256は`f0348037bf6796be694f9a00d58bcfeea0b963b8547f16bc5383a4c8b4257519`。Luna / xHighによる5b transport/bridge本体と5cの設定・起動ゲートの実装へ進む。PARのRFC 9126ギャップは開示のみ。5aのrelayからASへの証明を、まだ未検証のGateway直結transportや個別token失効の証明には扱わない。

以下は方式選択時点の設計契約である。

2026-10-02、**方式選択と設計契約をレビューし、PR #5としてmerge済み**。[ADR 0012](../decisions/0012-third-party-as-mtls-transport.md)を正本とする。production plugin、設定、realm、実装PRは作っていない。live環境も変更していない。WP5の開始には依存WPの受入が必要。Opusレビューへの補強として[Keycloak側peer証跡契約](third-party-as-peer-evidence.md)を追加し、WP5冒頭のAS-MTLS-OBS-01で計測/claimの成立を確認してから本体実装へ進む。

対象はKong 3.16.0.0の**3rd Party GatewayからASへの内部HTTP呼出し**。API Gatewayのstock mTLS introspection、3rd Party → APIのService client certificate、browserのHTTPSは別責務である。DPoP、専用失効制御、完全適合の追加guardは含めない。

## 固定版の技術確認

cached arm64 imageをread-onlyでexportし、選択moduleをローカルのGit管理外へ抽出した。コンテナは起動していない。

| 項目 | 確認結果 |
|---|---|
| image | `kong/kong-gateway:3.16.0.0`、arm64 |
| local image ID | `sha256:d2cd92f969c5960265288b9a54accd213d62801ba6ef001dba75a1c340b96d2d` |
| RepoDigest | `kong/kong-gateway@sha256:e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4` |
| stock PKJWT PAR/revoke | TLS cert/keyなし。PKJWTのaudience引数はissuer |
| stock PKJWT token/refresh | TLS cert/keyなし。audience引数はtoken endpoint。今回のaudienceにはbridgeを継続使用 |
| stock TLS branch PAR/token/refresh/revoke | TLS cert/keyあり。Route Aを維持し、Route B token/refreshにも使用 |
| discovery | cert optionを低水準HTTPへ渡さない |
| JWKS | libraryはcert optionを受け取れる。pluginの共有cache取得は別途補完が必要 |
| HTTP境界 | 既に生成されたclientもmodule methodを参照するため、`request_uri` decoratorがexact moduleの呼出しを受け取る |
| retry/cache | SDKは同じ認証bodyを再送する場合がある。metadataは共有cacheと別threadで取得される |

unchanged vendor bytecode + disposable decorator/interface mockの**42チェックがpass**。証跡は`.generated/dp0-20261002/offline-probe-results.json`、vendor identityは同ディレクトリの`vendor-module-identities.json`。probe SHA-256は`391558ec1d91a44c91f46028b40266ec348b370aab70b65d3172764f3562bdb9`。公開成果には挙動の要約だけを載せ、private source/bytecodeを含めない。

確認はHTTP option生成・delegate呼出し・mockした並行request分離である。HTTP response、crypto、cert parsing、clock、request contextはmock。**実TLS、実JWT署名、Keycloak 26.7.4受入、Kong worker lifecycle/hot configure、OpenResty cdata lifetimeの確認ではない**。実装用imageは各対象architectureでversion/module driftを検査する。master sourceやContext7のmain documentationだけで固定版を認定しない。

## 呼出しinventoryとidentity

以下で`I = https://localhost:8444/realms/fapi-demo`、`R = https://keycloak:8443/realms/fapi-demo`、`O = R/protocol/openid-connect`。URLは完全一致、許可methodも固定。userinfo等の未登録呼出しは拒否し、追加するならDesign ownerへ戻す。

| 呼出し | method / network URL | TLS identity | OAuth client認証 / 生成責務 |
|---|---|---|---|
| stock discovery | GET `I/.well-known/openid-configuration`を**`R/.well-known/openid-configuration`へ固定mapping** | metadata cert | なし |
| bridge独自discovery | GET `R/.well-known/openid-configuration` | metadata cert | なし。bridgeがissuer一致を検査 |
| stock JWKS | GET `O/certs` | metadata cert | なし |
| Route A PAR | POST `O/ext/par/request` | Route A cert | stock `tls_client_auth` |
| Route A token/refresh | POST `O/token` | Route A cert | stock `tls_client_auth` |
| Route A revoke | POST `O/revoke` | Route A cert | stock `tls_client_auth` |
| Route B PAR | POST `O/ext/par/request` | Route B TLS cert | stock PKJWT + transport decorator |
| Route B token/refresh | POST `O/token` | Route B TLS cert | stock TLS branch + bridge signer delegate + transport decorator |
| Route B revoke | POST `O/revoke` | Route B TLS cert | stock PKJWT + transport decorator |

Keycloakのback-channel dynamic設定を維持し、内部URLで取得したdiscoveryのissuerは`I`、token/PAR/revoke/JWKSは表の値であることをMETA-01/02で確認する。token/revocationのmTLS aliasは同じ内部URLを明示設定する。PAR aliasがmetadataにあれば同じURLへの一致を検査し、なければ通常PAR endpointにmTLSを付ける。aliasの動的追従や未知のURLへの書換えをしない。現在のmetadata値と一致しなければ、Workerが検査を外さずDesign ownerへ戻す。

discoveryのlocator mappingはissuer・OAuth audience・browser authorization/end-session URLを変えない。SNIは内部接続先`keycloak`とし、開発CAとSANでserverを検証する。stockとbridgeで別のmetadata identityを使わない。cold/shared cache、background rediscovery、JWKS light-threadでも常にmetadata certを選ぶ。

## Custom pluginの契約

### `fapi-as-mtls-transport`（新規、3rd Partyだけ）

- 3rd Partyの`KONG_PLUGINS`へtransportとbridgeを必須ロードし、API側では両方をロードしない（entityが無いだけでは不可）。起動preflightは下の「デモ入口のpreflightゲート」を必須段階として実施し、不一致なら3rd Partyをready/デモ入口公開にしない。ロード結果とwrapper/registry readyはAS-TRANSPORT-LIFECYCLE-01でworker内から観測する。global entityを1つだけ置く。priority **1100**、bridge **1060**、OIDC **1050**。実装時にexact runtimeで順序を確認する。API Gatewayでは有効化しない。
- `init_worker`で`resty.http.request_uri`を一度だけdecorateする。元関数を保存し、重複wrapを拒否する。private SDK module/fileやNGINX TLS終端を書き換えない。
- worker起動時の非機密bootstrap値として`FAPI_AS_TRANSPORT_ISSUER=I`、`FAPI_AS_TRANSPORT_INTERNAL_ORIGIN=https://keycloak:8443`を必須にする。configure前/不正時/無効化時も、これらAS originへの呼出しを証明書なしで通さない。その他のKonnect/control trafficにはcertを付けない。bootstrap値がNGINX workerから読めることを起動testで確認し、未設定/不可視ならreadyにしない。
- `configure`で全設定を検査し、read-only mountからcert/keyを読み、worker-local registryを作る。global設定の重複、origin/endpoint/Route不整合、欠けた鍵、cert/key不一致、期限切れ、誤ったEKUはfail closed。readyになるまで対象Routeのaccessを拒否する。
- `access`でserverが解決したRoute UUIDから`kong.ctx.shared.fapi_as_transport`へidentityとregistry epochを固定する。header/query/bodyからRouteやcertを選ばない。並行requestでworker-globalな「現在のRoute」を使わない。
- credential POSTは有効なRoute context必須。metadata GETはcontextなしでも専用certを使う。public/internal AS originの未登録method/URL、およびFAPI処理context内の外部URL/HTTPは拒否する。inventory外の通常trafficはcontext外なら変更しない。
- 引数tableとheader tableをcopyし、cert/key、`ssl_verify=true`、接続先に対応するSNIを設定する。fixed mapping後のURLは`R`、Hostは`keycloak:8443`、SNIは`keycloak`に揃え、caller供給Host（大小文字違いも）を破棄する。issuer/aud・browser URL・Locationは書き換えず、3xxは拒否する。stockが渡したcertはfingerprintで一致を確認する（cdata pointer equalityではない）。相違を黙って上書きしない。PKJWT signing keyをtransport pluginに渡さない。
- certは`ngx.ssl.parse_pem_cert`、keyは`ngx.ssl.parse_pem_priv_key`のopaque cdataを保持し、libraryが要求するchain/key型で渡す。GC前にrequestが終わるまでregistryの参照を保持する。単一x509 objectをchain pointerとして渡さない。
- デモでは`keepalive=false`、`ssl_reused_session=false`。pool namespaceにもidentity/epochを含める。exact imageの既定pool名はcert hashを含むが、デモの証跡は新規handshakeで取得し、接続再利用へ依存しない。
- HTTP 3xxはlibrary/SDKへ返す前にsanitized errorへ変え、Locationへ追従しない。server検証を弱めるfallback、certなし再試行、proxy経由の迂回を禁止する。
- request-scopedに`(logical_route, endpoint_kind, grant_type, canonical_form_digest)`を記録し、**同じ送信を再びnetworkへ出さない**。formは一度だけdecodeし、`client_assertion`/`client_assertion_type`を除外してparameter名順に正規化・SHA-256化する。stock assertionが再生成されても同じkeyとする。重複parameterは拒否し、forwardする正常なform値は変えない。PARと各token grantは同request内で最大1送信、revokeは`client_id + token`のdigestをkeyとし`token_type_hint`の差でも再送を通さない。refresh/accessの異なるtokenのrevokeは別keyで両方許可する。digestはsigner呼出し前に送信済みとして固定し、送信失敗時も解除しない。生token/bodyは保持しない。SDKのretryが同じassertionやcode/refresh/revokeを再送する場合はfail closed。GET metadataの再取得は許可する。生body/assertionをglobal registryやlogへ保存しない。
- stock PKJWTのPAR/revokeでformの`client_id`が省略される場合は、trusted Route registryのclient IDとassertionの`iss/sub`を照合する。省略だけで拒否せず、存在する値が異なる場合は拒否する。revokeの重複検査に必要なclient identityもregistryから導く。元のformへIDを補完せず、本文とstock assertionを維持する。RFC 9126のPARギャップは[ADR 0019](../decisions/0019-wp5-stock-claim-fixture-boundaries.md)へ記録し、完全準拠を本デモの完了条件にしない。
- configureの同一内容の再通知はidempotentとする。鍵/endpoint/identityの変更やplugin無効化は対象経路をfail closedにし、restartで新registryを作る。hot rotation・無停止再構成は今回の範囲外。nil configでwrapperを外してHTTPSへ戻さない。

公開APIの仕様は[resty.http](https://github.com/ledgetech/lua-resty-http)、[PEM parsing](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#parse_pem_cert)、lifecycleは[Kong custom plugin handler](https://developer.konghq.com/custom-plugins/handler.lua/)を参照する。これらの最新版documentationと固定imageの挙動を分ける。**このmethod decorator自体はworker-wide monkeypatchであり、公式のOIDC標準設定・本番推奨方式ではない。** 他pluginとの干渉はWP5で検証する。

### デモ入口のpreflightゲート（OMD-01）

これは警告logではなく、**通常デモの3rd Party入口/UIを開く前の必須ゲート**である。hybrid DPは非公開状態で起動し、CPから設定を受領してよい。worker起動時だけにglobal entityの存在を要求し、設定到着前に永久停止させる方式にはしない。

1. `make validate`でGateway別composeの`KONG_PLUGINS`を照合する。3rd Partyはtransport/bridgeの両方が必須、APIは両方とも禁止。bootstrap値の配置とdecK stateのtransport global entityが有効な1件だけであることも確認する。secretの値は出力しない。
2. 設定反映後、AS-TRANSPORT-LIFECYCLE-01のsanitized worker観測で、全workerの実ロード・wrapper設置・registry ready epoch・期待Route UUID/config一致を確認する。CP/decKにentityがあるだけではreadyとしない。未達/timeout/不一致はfailとする。
3. 1・2がpassするまで、通常3rd Party入口とUIは未起動または閉鎖状態を維持する。Workerはmake target/compose依存等の実装方法を選んでよいが、失敗時に非zeroで終了し、入口/UIを開かないことを受入で証明する。再起動/設定変更時はゲートを閉じ、再照合後に開く。新しい管理APIや本番用監視基盤は追加しない。

transport未ロード時、Route Aにbridge access拒否はない。stock POSTにcertが付いてもmetadata mTLSを保証しないので、上の入口ゲートで通常トラフィックを防ぐ。transportだけ/両pluginを外すnegativeでは、入口/UIが開かず、Route AのmetadataがASへ送られないことを確認する。observerのcertなし検出は独立した対照試験であり、既に送った通常トラフィックを事後検出するだけでpassにしない。Route Bでは既存のready context/epoch拒否も維持する。計測spikeは[peer証跡契約](third-party-as-peer-evidence.md)の隔離fixtureからだけ行い、通常デモ入口を開く代わりにしない。

PR #13の[WP1詳細設計](third-party-foundation-design.md)はこの未送信条件を、起動直後のstock background/metadataにも適用する。UI停止だけでは成立と判定せず、CP通信は許可しつつASのpublic/internal origin到達を閉じるbootstrap段階を要求する。全worker generation/ready/configの照合後だけ開放し、変更・再起動で閉鎖する。具体的なmake/compose機構と実証はWP5-BOOTSTRAPの受入対象。不成立ならneeds-designへ戻す。

### 設定の形（新規schemaの設計、既存設定値ではない）

global transport configはtest専用の`evidence_correlation_enabled`（既定false、[peer証跡契約](third-party-as-peer-evidence.md)のserver生成相関header用）と、`issuer`、`internal_origin`、`discovery_url`、`jwks_url`、`par_url`、`token_url`、`revocation_url`、`metadata_certificate_file`、`metadata_key_file`、`routes`を持つ。`routes`の各要素は`route_id`、`logical_route`（A/B）、`client_id`、`certificate_file`、`key_file`を持つ。任意URL、inline PEM/private key、動的fallbackの設定は提供しない。

PKIは`.generated/pki/third-party-metadata.crt`と`.key`を追加し、container内では`/etc/kong/fapi/third-party-metadata.crt`と`.key`へread-only mountする。開発CA、RSA 3072 bit、clientAuth EKU、30日以下。Route A/Bと別鍵で、OAuth clientとしては登録しない。Route cert/keyのfileは既存の`/etc/kong/fapi/route-a.crt/.key`、`route-b.crt/.key`を使い、OIDC Certificate entityとfingerprintを一致させる。

### `fapi-client-auth-bridge`（限定変更）

- third-party用に`assertion_delivery: transport_delegate`を追加する。v1のheader modeを残す場合でも、本構成ではdelegate modeだけを使い、`token_post_args_client`のassertion header転送を外す。
- client供給assertionの拒否、issuer一致検査、鍵のfail closedは維持する。署名処理を自分のmodule APIへ抽出し、accessではRoute Bのcontextへtrusted signer callbackとepochを登録する。headerへJWTを生成・注入しない。Route Bではtransportが先に設定したready identity/epochが無ければ必ず拒否し、transport未ロード・未設定時もstock PKJWTへ進ませない。起動preflightはbridgeも未ロードの場合を含めて拒否する。
- transportがRoute B `O/token` POSTの送信直前にcallbackを1回だけ呼び、formへ`client_assertion`/typeを設定する。code exchangeとrefreshそれぞれで新しいPS256署名、random 32-byte jti、`iss=sub=client_id`、`aud=I`文字列、`iat=送信時`、`exp=iat+60`を生成する。署名失敗時はnetworkへ送らない。
- stock TLS branchのformを安全にdecode/encodeする。grant/redirect URI/code/verifier/refresh tokenを変えず、client供給値とのmergeや二重assertionを禁止する。request bodyとContent-Lengthを一致させる。transportが元のoperation digestを記録してから署名するため、SDK retryでfresh JWTを作って再送を通すこともない。
- PAR/revokeはstockがPS256/issuer audienceで生成するJWTを使う。送信境界で期待するclient ID/aud/alg/jti/iat/exp形式を検査し、`aud`がIの文字列、`alg=PS256`、`iss=sub=期待client_id`、非空jti、整数iat/exp、`0 < exp-iat <= 60`、`iat <= now < exp`、残存TTL >= 5秒をすべて満たさなければ送らない。stockのclaimを黙って修正しない。signatureの受入はASのnegative fixtureで検証する。再送を許容するためにjtiを再生成しない。
- bridgeのmetadata cacheとsigning key cacheもregistry epochへ結びつける。変更時はrestart、古い成功cacheで新規送信を認めない。callbackや秘密鍵をlog/response/stateへ出さない。

## WP5の必須fixtureと証跡

WP5の最初に[Keycloak側peer証跡契約](third-party-as-peer-evidence.md)のAS-MTLS-OBS-01を通す。HTTP optionが存在するだけではpassにしない。AS/test harnessの**server-side TLS peer certificate・検証結果**と、処理結果を対応付ける。正規AS testではKeycloak `request`モードへ有効な開発CA client certを提示する。`request`はcertなしも受け付けるので、certなしfixtureは別途その制約の対照証跡とし、AS全入口のmTLS強制とは説明しない。

| ID | fixture / 判定 |
|---|---|
| AS-MTLS-OBS-01 | test-only Keycloak observerのhook/build、peer chain、ID相関、certなし対照/未信頼・期限切れTLS拒否、stock PAR/revokeのclaimを先に確認。不成立なら本体実装前にneeds-design |
| B-TRANSPORT-01 | PAR、code exchange、refresh、refresh/access revokeを別operationとして記録。全てRoute B peer thumbprint + chain検証成功 + PKJWT client認証成功。token/refreshではcnf一致。revoke HTTP 200を個別失効の証明にしない |
| AS-META-MTLS-01 | cache clear/restart後にA先行/B先行を実行。stock discovery/JWKS、bridge discovery、background再取得、JWKS child-threadのpeerが全て専用metadata cert。warm cacheのnetwork省略はskip/no-fetchと記録し、mTLS成功と数えない |
| B-AUD-01/02、B-PKJ-01 | token/refresh/PAR/revoke全部のaudがissuer文字列、alg PS256、iss/subが新client ID、TTL 60秒以下、operation間でjti相違。実署名でASが受入れる |
| B-AUD-01（negative fixture） | endpoint audience、配列aud、別issuer、期限切れ等は送信guardで拒否しnot_sentを確認。実署名改変/期限切れをASへcontrolledに直接送る試験も別に行う。guard拒否とAS拒否はfixture/rejection_layerで区別し、Keycloakが全claimをFAPI形式どおり拒否すると未検証のまま主張しない |
| B-JTI-01 | 同一assertionをASへ直接2回送るcontrolled negative fixtureでreplay拒否。通常plugin経路のSDK retry抑止とは別に実施する |
| B-CERT-01、TLS-01 | cert/key欠落・不一致、未信頼/期限切れcert、server CA/SAN不正。送信前またはTLSで拒否。certなしHTTPSへのfallbackなし |
| AS-TRANSPORT-GUARD-01 | missing context、未知endpoint/HTTP/外部origin/3xx、conflicting identity、同一POST retry（fresh assertionでも拒否）、signer欠落/期限不足・TTL上限超過を拒否。同requestのrefresh/accessの異なるtoken revokeは両方許可し、同tokenのhint変更再送は拒否。warm/cold、A/B同時実行で取り違えなし |
| AS-TRANSPORT-LIFECYCLE-01 | worker startup、Gateway別の実ロード状態（3rd Partyは両pluginあり、APIは両方なし）、未ロード/未設定時のpreflight（transportだけ/両plugin欠落で入口/UI閉鎖・Route A metadata未送信）・Route B bridge拒否、configure前、同一iterator再構築、二重global config、invalid/nil configure、restart、background/light-thread、別pluginの通常HTTPを検証。配置・順序・epochと実際のTLS certを確認 |
| LEAK-01 | error/log/UI/evidence/stateにtoken/code/cookie/assertion/鍵/完全certなし。callbackとfile内容も非公開 |

証跡JSONは`.generated/evidence/<scenario-id>.json`。各operationに`scenario_id`、`fixture`、`request_id`（秘密情報でない相関ID）、`logical_route`、`endpoint_kind`、`method`、`identity_kind`、peer thumbprint、`tls_peer_verified`、`server_validation_negative_pass`（該当時）、`oauth_auth_method`、HTTP status、`assertion_aud_is_issuer`/`alg`/`ttl_seconds`/`jti_distinct`、`cnf_matches`（該当時）、`cache_state`、`registry_epoch`、resultを持つ。AS側peer証跡の取得元はtest-only Keycloak observerとし、AS側の同じID/method/pathの行へ1:1 joinする。送信Host、observer image/patch/TLS設定receipt、peer_cert_present、peer_chain_pkix_valid、verification_basis、negative TLS receiptも記す。peer存在だけでtls_peer_verified=trueにしない（詳細はpeer証跡契約）。PRはthumbprint先頭12文字等のsanitized summaryだけにする。raw JWT、jti、body、完全certificate、TLS session keyを記録しない。

一次観測はpeer証跡契約のtest-only Keycloak source-instrumented imageに固定する。TLS test ASはretry/threadの補助試験だけに使い、Keycloak向けPAR/revoke/metadataのpeer証跡を代用しない。標準Keycloak imageのデモflowも別途確認し、計測imageだけで動作済みとしない。packet captureの推測だけでmTLSと判定しない。

## 実装着手後の戻し条件

callback contextが失われる、metadata取得が別HTTP APIへ変わる、worker-wide decoratorが他pluginに干渉する、固定alias/issuerが成立しない、server-side証跡を取れない、またはstock PAR/revoke JWTが文字列aud/PS256/TTL等の送信条件を満たさない場合は、WP5冒頭のspikeで本体実装前にneeds-designとする。claim不適合時の第一候補はPAR/revokeもstock TLS branch + signer delegateにする案だが、採否はDesign ownerが決め、Workerは切り替えない。Workerはprivate SDK patch、追加proxy、HTTPS downgradeを自己判断で採用しない。Design ownerが別adapter案とscope/工数を再提案する。
