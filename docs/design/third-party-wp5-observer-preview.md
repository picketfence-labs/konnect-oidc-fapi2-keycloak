# WP5 5a Keycloak observer spike preview

## Current state

This branch is based on main `a84e1dfcc55f1c14788110f17dc7e2c5a96bda76`. WP3 #9 has a current 37/37 acceptance receipt; its separate normal Control Plane migration remains unapplied. For WP5, full-reactor V4 remains withdrawn. The corrected published-JAR test image `wp5-as-peer-observer:20261004-minimal-v3` (ID `sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953`) built with pinned Temurin 21 and passed Root's independent archive review. Direct-runtime v3 passed the 40/40 observer gate. The separate re-entry r4 runtime probe was accepted with canonical observer counts `[1, 1, 0]` and re-entry counts `[[], [2, 3, 4], []]`; all three PAR responses were HTTP 401. This demonstrates repeated-handler observation behavior, not successful stock PAR. Its terminal receipt is `/private/tmp/wp5-as-reentry-probe-run-receipt-20261004-v4-r4.json` (SHA-256 `0649988015f31ea238683540c8eab0be1991f8001a79a90ba3f73d6dc7e1b515`), with independent review `.generated/evidence/wp5-root-reentry-r4-terminal-review-1791092645025522000.json` (SHA-256 `126ad62aa0b6cd813466b44989390cceda1b701f33a983a357dcde6c7e3a56c1`). Root accepted the bounded v15 stock fixture as the WP5 5a demo gate; RFC 9126 client_id conformance and direct Kong-to-AS transport proof remain outside that acceptance.

| 5a gate | v15 result | Evidence boundary |
| --- | --- | --- |
| Stock PAR | HTTP 201; original PS256 assertion passed issuer/subject/audience/TTL checks and was forwarded unchanged | The PAR omitted `client_id`; the RFC 9126 gap remains recorded. |
| Browser/session/logout | Token response HTTP 200, callback HTTP 302, session cookie changed, and stock logout completed | Fixture-only demo flow. |
| Access and refresh revokes | Both stock revoke operations returned HTTP 200 | HTTP 200 does not prove the corresponding token is individually unusable. |
| AS peer observation | Three operation joins passed with the expected Route B certificate, chain count 2, PKIX, validity, and clientAuth-EKU checks | Relay-mediated evidence; it does not prove direct Kong-to-AS TLS transport. |
| Cleanup | Root independently verified owned Docker resources, listener, and private fixture absent | Image retained. |

The accepted v15 terminal receipt is `/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v15.json` (SHA-256 `f0348037bf6796be694f9a00d58bcfeea0b963b8547f16bc5383a4c8b4257519`); Root's independent audit is `.generated/evidence/wp5-root-stock-v15-terminal-review-1791101147900716000.json`. Full WP5/5b work remains separate.

The v14 stock run returned PAR HTTP 201 and joined its operation to the expected Route B peer row, then stopped after a fragment-based callback Location was rejected (`location_rejected`). Its immutable receipt is `/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v14.json` (SHA-256 `1c75fc9fbd6b401a2ad6c3e4bb44602d75a0ebf78ae8da0e470b750195a372e9`); Root independently verified cleanup in `.generated/evidence/wp5-root-stock-v14-terminal-review-1791100819574103000.json`. The v15 fixture set `login_tokens: null`, matching the documented [Kong authorization-code flow configuration](https://developer.konghq.com/how-to/configure-oidc-with-auth-code-flow/), and passed the bounded full-flow gate summarized above.

The first direct fixture attempt (v1) passed 30/32 cases but stopped on the expired-client TLS negative; its immutable receipt and supplemental cleanup record are retained below. The second attempt (v2) passed 39/40 cases, then failed observer row validation. Its immutable terminal receipt is `/private/tmp/wp5-as-mtls-observer-run-receipt-20261004-v2.json` (SHA-256 `e7d049f4e662e8cfdc62d11c9f797a2906ba84e55aa2c4b635e7527739aa7d61`). Root verified a complete bounded ON scan with 22 parsed rows, zero joins, and cleanup complete. All rows were fixed `observer_failure` entries with unknown endpoint/method/path, correlation ID `none`, and no peer metadata. The four TLS negatives were classified: client untrusted and expired both produced `SSLV3_ALERT_CERTIFICATE_UNKNOWN` over TLSv1.3 at `response_read`; wrong server CA and SAN were client-side `server_certificate_verify` failures at `handshake`. Their before/after HTTP liveness controls completed. This historical v2 attempt did not establish peer joins or repeated-handler runtime proof; the corrected v3 direct gate and separate r4 re-entry probe later supplied their respective evidence. At that point, stock-Kong PAR/revoke acceptance remained open; v15's later result is summarized above.

The pinned published Quarkus JAR proves that `UriInfoImpl.getPath(false)` throws `IllegalArgumentException` before reading the request context; an offline call against that actual JAR reproduced the exception class. This is the definite source/API defect behind the old helper call, while the v2 runtime receipt did not retain the Java exception class itself. The helper now reads `RoutingContext.request().path()` and accepts only five exact absolute paths before storing their canonical no-leading-slash forms. Root's offline compile and 50 path controls passed against all 471 identity-checked published JARs with JDK 23 `--release 17`; the corrected seven-file v3 context then built successfully with pinned JDK 21 and passed independent archive/bytecode review. The v3 direct fixture confirmed positive peer-observation cases; later re-entry r4 confirmed the repeated-handler trigger at runtime. At that point, stock-Kong claim/session/revoke acceptance remained unresolved; the later v15 result is summarized above.

## Stock Route B fixture history (v1-v7; later v14-v15 results above)

This fixture covers one public Kong Gateway 3.16.0.0 Route B authorization start and the resulting stock PAR. It uses client `kong-fapi-pkj-mtls`, issuer/audience `https://localhost:8444/realms/fapi-demo`, the existing bridge header mode, and the real observer Keycloak as the final TLS peer. The stock plugin makes the authorization request; the fixture does not call private Kong modules or rewrite/re-sign the assertion. Browser authorization, code exchange, session, and logout revocations proceed only after the PAR and observer-join gates pass.

The first fixture attempt (v1) stopped during startup because its wrapper called `/docker-entrypoint.sh`, while the pinned Kong image uses `/entrypoint.sh`. Root's immutable v1 terminal receipt SHA-256 is `24da33f60085f2fdc5d4ffa61ca87c93c0da4d51f70e5ec4d2f2ab50bc27a6a0`; independent review `.generated/evidence/wp5-root-stock-v1-terminal-review-1791090386611238000.json` confirms the auth-start status and PAR are both absent, stage 2 is `not_run`, exact Docker resources are absent, all three ports are free, and the private fixture was removed. The v2 attempt stopped before auth-start when its startup container-state inspection hit `command_timeout`; its immutable terminal receipt SHA-256 is `19f514a6e23d1896ff321585a8c4f4718a0f7e7ecd1f48c4a1399c966c996505`, and Root independently confirmed cleanup. The stock v3 fixture was prepared but never started while Root tested network topology; no v3 auth-start or PAR occurred. Network control showed that the Docker internal network could not reach a host-loopback published port, while the normal dedicated bridge could (`.generated/evidence/wp5-root-loopback-topology-control-1791091960731873000.json`). Neither v1 nor v2 sent a stock PAR, and v3 produced no runtime result. All earlier receipts remain immutable.

The unused v3 host fixture was removed after Root matched its 21-file manifest and confirmed its Docker project, volume, and network were absent; evidence is `.generated/evidence/wp5-root-unused-stock-v3-cleanup-1791092116300874000.json`. V4 host-only preparation completed at `/private/tmp/wp5-as-peer-stock-par-route-b-20261004-v4` with 21 mode-0600 files in a mode-0700 directory. Its prep receipt is `/private/tmp/wp5-as-peer-stock-par-prep-receipt-20261004-v4.json` (0600, SHA-256 `c586ad31c2b7262737c51da0a9b43542dc8101c8cf67c6f21e617e7c377bc97d`), with separate v4 intent and terminal receipts. Host preparation reads only the existing host `KONG_LICENSE_DATA` input and copies that one value into a mode-0600 fixture license file for Kong Gateway's documented `KONG_LICENSE_PATH`. It does not read `.env` or pass host environment values to Docker. The license value is not printed or recorded; only private file inventory hashes and fixed status fields enter the receipt. If the existing input is absent or invalid, preparation stops without fetching a license.

The fixture pins cached linux/arm64 images: Kong Gateway `kong/kong-gateway:3.16.0.0@sha256:e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4` (local image ID `sha256:d2cd92f969c5960265288b9a54accd213d62801ba6ef001dba75a1c340b96d2d`), Keycloak image ID `sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953`, and the preflighted relay image ID `sha256:8832f9ad3ee60b05d2d0e87a1e998eec2b211d65634a5d073ce8c2193b6ae831`. No build or pull is part of this scope. Compose owns exactly three services (`keycloak`, `kong`, and `as-spike-harness`), one H2 volume `wp5-stock-par-route-b-v4-data`, and one fixture-scoped dedicated bridge `wp5-stock-par-route-b-v4_default`. This bridge replaces the v3 `internal: true` network because the read-only host-loopback control showed that only the dedicated bridge reaches the host-published loopback Keycloak port; the evidence is the topology control above. Host services remain published only on loopback ports 8443, 8444, and 19445. Resource limits total 3.5 CPUs and 8 GiB; startup is capped at 180 seconds, each command at 60 seconds, the fixture run at 12 minutes, and cleanup at 120 seconds. The Kong wrapper calls the image's `/entrypoint.sh kong docker-start`. During TLS readiness, the runner queries the exact owned Kong service with `docker ps -aq --no-trunc`, verifies its 64-character ID against `docker inspect`, and checks owner/phase/image/state. Read-only query timeouts or transient Docker command failures cause another check within the shared 180-second startup deadline; TLS success cannot advance to auth-start until Kong is confirmed running. An inspected `exited` state stops promptly.

The issuer stays `localhost:8444` because it is the stock plugin's configured issuer and audience. The Kong entrypoint maps only `localhost` in a fixture-local DNS hosts file to Docker's host-gateway address. Before the authorization request, the runner checks TLS connectivity from the Kong container to that gateway on 8444 with SNI and hostname `localhost`, using the fixture CA. If that route fails, the runner stops before the stock request and records a fixed failure category; it does not change issuer, audience, add a proxy, or open a non-loopback listener.

One reviewed attempt runs the following sequence: start the three fixed services, wait for TLS readiness, pass the host-gateway TLS check, request `GET /api/fapi/pkj-mtls` once without following redirects, then read the relay's sanitized status once. The gate requires the stock request to return 302, exactly one original-form PAR to return 201, and a verified PS256 assertion whose `iss` and `sub` equal `kong-fapi-pkj-mtls`, whose `aud` is the exact issuer string, and whose TTL is at most 60 seconds with at least five seconds remaining at send time. A 200 response, any 4xx, invalid claim, transport failure, or missing/duplicate observer row fails the attempt. The PAR operation ID must join to exactly one observer POST row with the expected Route B certificate DER digest, PKIX/validity/clientAuth-EKU checks, and no observer error. Discovery/JWKS rows are separately counted within a small fixed allowance and never count as peer evidence.

The harness forwards the received assertion form unchanged. It records only fixed operation IDs, endpoint/method/path, claim booleans and bounded TTLs, HTTP status, fixed OAuth error enum, and strict observer fields. It never records the JWT, `jti`, request or response body, cookies, password, license value, PEM material, or raw logs. `relay_attempted=true` with `forwarded=false` means the TLS/HTTP exchange did not complete; it does not prove that the POST was unsent. Only a pre-forward validation guard can establish `not_sent`.

The historical v4 preparation used this command when the runner was pinned to v4 paths. It is retained as history only; the current runner uses v7 paths, and neither old nor current exclusive paths should be replayed:

```sh
rtk proxy /private/tmp/wp2-owner-venv-_gmgs6y3/bin/python \
  tests/harness/wp5_observer/stock_fixture.py prepare
```

The v4 exclusive prep receipt, intent, and terminal receipt paths are `/private/tmp/wp5-as-peer-stock-par-prep-receipt-20261004-v4.json`, `/private/tmp/wp5-as-peer-stock-par-run-intent-20261004-v4.json`, and `/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v4.json`. They are immutable history; the v4 attempt already ran once and must not be replayed.

The runner verifies exact image IDs and resource absence before start, validates ownership labels before cleanup, stops the services, captures and scans bounded logs in memory, downs only this Compose project and named volume, checks resource absence and loopback port release, and then removes only the fixed private fixture directory. A failed or incomplete run remains failed/needs-design; it cannot report pass without the stock claim gate and the observer join.

V4's single auth-start returned HTTP 500 after the stock plugin sent a PAR to the local relay. The relay recorded fixed result `par_form`, `relay_attempted=false`, and `forwarded=false`; it rejected the form before assertion verification and did not send it to Keycloak. The observer recorded only three auxiliary metadata rows, all correlation-invalid, so there is no PAR peer evidence. Root's terminal audit is `.generated/evidence/wp5-root-stock-v4-terminal-review-1791092440403184000.json`; cleanup was independently verified. The receipt did not retain raw form keys, so the exact rejected condition is not proven. The cached exact Kong schema has `response_mode` default `query`, and the stock authorization builder adds a non-null response mode to the PAR. V4's allowlist omitted that field. V5 accepts it only with value `query`; unknown field names, client ID, response type, and other mode errors now have separate fixed categories. Signature, issuer/audience, PS256, TTL, one-time `jti`, and byte-for-byte forwarding gates remain unchanged.

V5 host preparation completed at `/private/tmp/wp5-as-peer-stock-par-route-b-20261004-v5` with 21 files (directory 0700; files 0600). Prep receipt `/private/tmp/wp5-as-peer-stock-par-prep-receipt-20261004-v5.json` is mode 0600, SHA-256 `45b19b628f96c8522649a47c31f1dfdb8ffa61baaa617b8a50e8da8cc2b7b371`. The single approved stage-1 command ran once:

```sh
rtk proxy /private/tmp/wp2-owner-venv-_gmgs6y3/bin/python \
  tests/harness/wp5_observer/stock_fixture.py run --approved-single-attempt
```

Do not replay it: V5's exclusive intent and terminal receipts are `/private/tmp/wp5-as-peer-stock-par-run-intent-20261004-v5.json` and `/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v5.json`. The terminal receipt SHA-256 is `7c2d9f71fde9d626e7e04a209f70c0f0f3b8256f5543ff36f64584a51a1c06ce`; Root's independent terminal/cleanup audit is `.generated/evidence/wp5-root-stock-v5-terminal-review-1791093611939675000.json`. It confirms preparation/intent/source-hash consistency, exact pinned images, absence of the owned project/volume/network, release of ports 8443/8444/19445, and removal of the private fixture tree.

V5 auth-start returned HTTP 500. The relay rejected the real stock PAR with fixed result `par_client_id`, `relay_attempted=false`, and `forwarded=false`, before cryptographic verification or forwarding to Keycloak. The observer captured three auxiliary metadata rows, all `correlation_invalid`; no PAR peer claim was established. Read-only inspection of the pinned stock SDK shows its `private_key_jwt` helper removes `client_id` from PAR and revocation form parameters before encoding. RFC 9126 section 2.1 requires `client_id` in a PAR request ([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1)). The accepted demo contract prioritizes the unmodified Kong stock request and records this specific RFC gap; it does not claim RFC 9126 or full FAPI 2.0 conformance. The relay accepts an absent form `client_id`, rejects a present mismatch and all duplicates, and preserves the original body and signed assertion byte-for-byte. Assertion signature, `iss`/`sub`, exact issuer `aud`, TTL, one-shot, final send-time TTL, and observer join gates remain strict. No field is inserted and no assertion is re-signed. The design record is [ADR 0019](../decisions/0019-wp5-stock-claim-fixture-boundaries.md). The V5 failed receipt is immutable; its cleanup was independently audited. Session/code exchange and access/refresh revokes remain `not_run` in this stage-1 runner.

V6 was prepared before the terminal field name was narrowed to the specific `client_id` RFC requirement; it was superseded before execution, and its 21-file private tree was removed after manifest verification. Its prep receipt remains immutable. The V7 fixture was prepared at `/private/tmp/wp5-as-peer-stock-par-route-b-20261004-v7` (21 files, directory mode 0700, file modes 0600). Prep receipt `/private/tmp/wp5-as-peer-stock-par-prep-receipt-20261004-v7.json` is mode 0600, SHA-256 `cc6ae13bb99a677ce979f78dbd823d60b939b7fbacc88da16d2d1c6ee6e03d0b`; its schema is `wp5-stock-par-prep-v7`. That runner used project `wp5-stock-par-route-b-v7`, volume `wp5-stock-par-route-b-v7-data`, network `wp5-stock-par-route-b-v7_default`, and phase `stock-par-stage1-v7`. Its exclusive intent and terminal receipt paths were `/private/tmp/wp5-as-peer-stock-par-run-intent-20261004-v7.json` and `/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v7.json`. It used the already pinned cached Kong, Keycloak, and relay image IDs listed above, with no build or pull, and the dedicated normal bridge needed for the loopback host-gateway route. Only the existing host `KONG_LICENSE_DATA` value was copied into the private fixture license file; `.env` and other host credentials were not passed.

The V7 preview covered one stock PAR attempt. The runner started exactly the three fixture services, waited for TLS readiness, verified the host-gateway TLS route, requested the stock authorization start once without redirects, and read one sanitized relay snapshot. PAR could omit `client_id`; if present it had to equal `kong-fapi-pkj-mtls`, and duplicate parameters were rejected. After the actual PS256 assertion passed fixed `iss`/`sub`, exact issuer audience, TTL ≤60 seconds, remaining TTL ≥5 seconds, and one-shot checks, `relay_once` received the exact original request body bytes and the same assertion string. A test confirmed these bytes and assertion were unchanged. The event recorded only `stock_form_client_id_present`; the terminal's `rfc9126_client_id_requirement_met` was false when the PAR omitted the field and was limited to that one requirement, not a general compliance claim. Demo gate success required stock auth-start 302, PAR 201, and exactly one valid observer row joined to the expected Route B certificate digest with PKIX, validity, and client-auth EKU checks. Missing or duplicate peer rows, claim failures, transport errors, or unexpected auxiliary rows failed the attempt.

After Root reviews the V7 prepared fixture and source hashes, the exact one-attempt command is:

```sh
rtk proxy /private/tmp/wp2-owner-venv-_gmgs6y3/bin/python \
  tests/harness/wp5_observer/stock_fixture.py run --approved-single-attempt
```

V6 and V7 were not run, and the V5 failure remains immutable. Their previewed cleanup was limited to the exact owned project, three labeled services, named volume, dedicated network, ports 8443/8444/19445, and their fixed private fixture. The later v15 run and cleanup are recorded above.


## Corrected published-JAR build v3 (completed; runtime is separate)

The fixed public inputs remain Keycloak 26.7.4 commit `aa9fe3fba0c6cd5770f19a49378c55f4378cf544`, release ZIP SHA-256 `a286e98b4296d4e75ee88d8527c7cd463b307caa022f088c9f22cffccc741fa1`, and original runtime JAR SHA-256 `57bda3c01502dc553029f2e96f3b7b79e6e3aefcc33be13f67b0b29a3e693a2c`. Context `/private/tmp/wp5-as-peer-minimal-image-build-20261004-v3/context` contains exactly seven public files, mode 0600 under mode-0700 directories; `context-manifest.json` SHA-256 is `ef35e30053f0a62a02635f8aa024569e9b6c5290f8ffc13373df5fe225e50893`. Root's independent context review passed, including helper SHA `550291bd8411ca4fa18c03709e7be730532a67bfc244ef4f6ab35cf73d540141`, unchanged handler/Dockerfile/compile script, and intact v1/v2 snapshots.

The exact cached bases were Keycloak image ID `sha256:dc0f6a6c61f4170f154b6dd89dfc160c839fd24989d2c798af2a7072498bfbac` at digest `sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`, and Temurin image ID `sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259` at digest `sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687`; both were cached for `linux/arm64/v8`. Context `/private/tmp/wp5-as-peer-minimal-image-build-20261004-v3/context` had seven public files and manifest SHA-256 `ef35e30053f0a62a02635f8aa024569e9b6c5290f8ffc13373df5fe225e50893`. The one approved bounded build used wrapper `/private/tmp/wp5-owner-host-bounded-v3-20261004.py` (SHA-256 `46d100944a828e0eff1aefff3124ca41d0c9427f343abf52527775c0330a81a9`), `--pull=false --no-cache --network=none --platform linux/arm64/v8`, and tag `wp5-as-peer-observer:20261004-minimal-v3`.

The command ran once and returned exit code 0 without timeout. Docker stdout/stderr were discarded by the wrapper, not scanned or retained. The image ID is `sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953`. Its immutable receipt is `/private/tmp/wp5-as-peer-minimal-image-build-receipt-20261004-v3.json` (SHA-256 `8f809827b499eb73b05eb365a1d28e26196a190cb7b6c2874702d7104abcc64a`); intent is `/private/tmp/wp5-as-peer-minimal-image-build-intent-20261004-v3.json`. Root's independent archive review passed: 471 JARs checked, 470 unchanged, one runtime JAR with the handler replaced/helper added, 256 other runtime archive entries unchanged, class major 61, handler ABI and hook order unchanged, and runtime JAR SHA-256 `3ef3660cf08ed1ca8b627852a4ddf625e05c18b189680e9bf38e0d9b08b4ded2`. Evidence is `.generated/evidence/wp5-root-minimal-built-image-review-1791083985580572000.json`. The build-only approval is consumed; it did not start a service or authorize the direct runtime.

The exact command that ran is retained as an execution record; do not replay it:

```sh
rtk proxy /private/tmp/wp5-owner-host-bounded-v3-20261004.py 1200 \
  docker build --pull=false --no-cache --network=none \
  --platform linux/arm64/v8 --tag wp5-as-peer-observer:20261004-minimal-v3 \
  /private/tmp/wp5-as-peer-minimal-image-build-20261004-v3/context
```

The wrapper had a 1200-second host deadline. Dockerfile `RUN` steps used `--network=none`; `--pull=false` and the cached-pin preflight avoided an explicit base pull. The image reports `linux/arm64` and labels `wp5-luna` / `observer-image-build-only`. No runtime container, Compose service, volume, realm, Gateway fixture, or normal environment was part of this build.

## Direct observer runtime v3 attempt (completed; direct observer gate passed)

The corrected image passed archive review, and the user separately approved one Keycloak startup/TLS attempt. Runtime code pins image ID `sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953` and tag `wp5-as-peer-observer:20261004-minimal-v3`. Root reviewed the code and focused runtime suite, prepared the fresh 17-file fixture, and passed independent PKI plus read-only Docker/Compose preflight. The source/fixture review is `.generated/evidence/wp5-root-direct-preflight-review-1791084160366181000.json`, Docker preflight is `.generated/evidence/wp5-root-direct-docker-preflight-1791084203507501000.json`, and terminal review is `.generated/evidence/wp5-root-direct-terminal-review-1791085120188078000.json`.

The single-service fixture used project `wp5-as-mtls-observer`, named H2 volume `wp5-as-mtls-observer-data`, project network `wp5-as-mtls-observer_default`, and loopback-only `127.0.0.1:19443`→container `8443`. It used a fresh mode-0700 host fixture with 17 mode-0600 files, minimal `fapi-demo` realm, server certificate/key and CA trust file mounted read-only, and no client certificate or key mounted into Keycloak. The preparation receipt is `/private/tmp/wp5-as-mtls-observer-prep-receipt-20261004-v3.json`; the fixture directory was removed during cleanup. Runtime intent is `/private/tmp/wp5-as-mtls-observer-run-intent-20261004-v3.json`; terminal receipt is `/private/tmp/wp5-as-mtls-observer-run-receipt-20261004-v3.json`, mode 0600, SHA-256 `93f3503abff52ee38449130bc131484664d0c96f8ad35e45b8a6f4924b97709c`. Preparation and runtime receipts use schema v3 and exclusive creation.

Root audited the terminal receipt: all 40/40 case gates passed across 34 operations. Observer OFF emitted zero rows; ON emitted 21 rows, of which 18 positive rows joined to the expected peer-certificate digests. The eight OFF/ON HTTP baseline statuses matched, Route A/B concurrent POST-token controls mapped correctly, no-certificate returned `peer_absent`, malformed/duplicate correlation controls returned `correlation_invalid`, and unknown-path 404 produced no row. All four TLS negatives and their eight bracketing HTTP/peer controls passed, with no observer row attributed to a negative TLS case. The bounded ON log scan completed. Root independently verified exact owned Docker cleanup, removal of the private 17-file fixture, port 19443 availability, retained image, and unchanged v1/v2 receipt hashes. This passes the direct AS-peer observation gate. The direct v3 fixture itself did not measure repeated handler invocation; the separate re-entry r4 probe later established it.

No normal services, Control Plane, realm update, stock Kong, or 5b operation was included. Stock-Kong signed PAR and both access-token/refresh-token logout revoke-claim cases remain before full 5a; 5b remains unstarted.

The host-only preparation and one runtime attempt are complete. Root's ready review is `.generated/evidence/wp5-root-direct-v3-ready-review-1791084332330129000.json`. The exact command that ran once is retained for audit only; do not replay it:

```sh
rtk proxy /private/tmp/wp2-owner-venv-_gmgs6y3/bin/python tests/harness/wp5_observer/runtime_fixture.py run --approved-single-attempt
```

The v2 run remains historical direct-runtime evidence (39/40 cases, 22 observer failures, zero joined rows); v1/v2 receipts and cleanup evidence remain immutable. V3 passes the direct observer sub-gate only; it does not complete full 5a or 5b.

## Observer source and hook contract

The source pin is Keycloak 26.7.4 commit `aa9fe3fba0c6cd5770f19a49378c55f4378cf544`. The pinned upstream handler SHA-256 is `9c751a303a52984a64a0cac5ba4dd07c2f639006608c2386df68f4ecba6d5e9d`. `patch_keycloak_source.py` requires this commit, a clean checkout, that exact handler hash, and one insertion anchor. It adds the helper and inserts one call immediately after `KeycloakSessionUtil.setKeycloakSession(currentSession)`, before `super.handle(requestContext)`.

The helper reads `FAPI_DEMO_AS_PEER_OBSERVER` first. Unless its value is exactly `true`, it returns before CDI, request, header, or peer-certificate access. Enabled mode uses a Vert.x `RoutingContext` marker for per-request deduplication. It takes the raw path from `routingContext.request().path()`, matches exactly five absolute `/realms/fapi-demo/...` paths, then stores only the canonical no-leading-slash path paired with its fixed method/endpoint. Encoded variants, extra prefixes, double slashes, unknown paths, and trailing slashes are not recorded. Keycloak `HttpRequest` remains the source for method, correlation header, and peer chain. Records contain only the ID, UTC time, fixed endpoint/method/path, peer presence, chain count, PKIX/validity/clientAuth-EKU booleans, a SHA-256 leaf thumbprint, and a fixed error enum. The helper never reads query, body, cookies, authorization, or arbitrary headers; observer errors do not alter endpoint handling.

The observer helper, source patcher, focused tests, and context preparer are tracked. The derived-builder Dockerfile's inventory-order correction remains part of the historical full-reactor build record; that V4 method was withdrawn. This preview, troubleshooting log, delivery plan, handoff, and session status record the earlier full-reactor outcomes, direct-runtime v1/v2 results, corrected published-JAR v3 build and archive review, and pending direct-runtime v3 approval. The upstream source is retained only in the private analysis directory, not in the worktree.

## v2 build-only attempt (completed; commands below are historical)

The builder base is the Linux arm64/v8 image `eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687`, already pulled and retained at image ID `sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259`. Its inspected config and network-none preflight confirmed Ubuntu 26.04 and Java/Javac 21. The v2 preview requires this exact local image ID and digest to remain present; if absent or mismatched, stop and prepare another preview instead of pulling under this approval. The host has no supported JDK 17/21/25. The [pinned Keycloak build guide](https://github.com/keycloak/keycloak/blob/26.7.4/docs/building.md) requires Git, so the preview adds a small derived builder with only the `git` package requested from the base image's configured Ubuntu 26.04 repositories, using apt's normal signature checks and `--no-install-recommends`. Both pre/post package inventories are sorted with `LC_ALL=C`, and `comm` runs with the same explicit locale. The derived image records the exact added package/version rows; after creation, its immutable local image ID is recorded. The [pinned Maven wrapper](https://github.com/keycloak/keycloak/blob/26.7.4/mvnw) has a Java download fallback and uses the Maven `.tar.gz` plus `tar` when `unzip` is absent, so neither `curl`/`wget` nor `unzip` is a required package. A network-none preflight will verify Java/Javac 21, Git, `tar`, `timeout`, shell/coreutils, and the exact OS before Maven begins. Missing or mismatched tools stop the build; no host toolchain or package install is planned.

The user-approved v2 attempt covered public-source acquisition, one derived-builder image build, network-none tool preflight, and one `quarkus/runtime` compile attempt. It did not include a server distribution retry, Keycloak runtime, realm import, direct TLS probe, stock-Kong fixture, or 5b. The build received no normal `.env`, `.generated`, Konnect token, Kong license, realm, account, certificate, or private key. Maven stdout/stderr and Docker build output were discarded. The compile exited 1; no source line, exception, failing module, or cause was preserved. The phase failure and cleanup are recorded in the immutable receipts listed above. The exact v2 commands below remain as an execution record and must not be replayed.

The v2 ownership names are `wp5-as-observer-builder-20261003-v2` (one `--rm` container reused sequentially), `wp5-as-observer-m2-cache-20261003-v2` (one labeled Maven cache volume), `wp5-as-observer-builder:20261003-5a-v2` (derived local image), and `/private/tmp/wp5-as-observer-build-20261003-v2/` (private source/output). The v2 intent and build receipt paths are `/private/tmp/wp5-as-observer-build-intent-20261003-v2.json` and `/private/tmp/wp5-as-observer-build-receipt-20261003-v2.json`, both exclusively created mode 0600. Root's read-only v2 inventory confirmed all these names absent, the retained base ID/digest exact, and Docker capacity at 4 CPUs / 9.7 GiB; repeat the exact absence and base identity checks immediately before any execution. The resource cap is 4 CPUs / 8 GiB plus `MAVEN_OPTS=-Xmx4g`; do not change Docker VM settings. Create the workspace parent and child directories mode 0700. Docker build context is only `tests/harness/wp5_observer/builder/`, containing the reviewed Dockerfile; the repository, `.env`, `.generated`, and other assets are never sent to the daemon.

After approval, acquire only the public pinned source on the host. Git runs on the host for checkout and patch preconditions; the Keycloak build guide also requires Git in the build environment, hence the derived builder. This host has no `timeout` or `gtimeout`; use the reviewed `/private/tmp/wp5-owner-host-bounded.py` wrapper for host Git and Docker commands. It uses the standard Python runtime, bounds the child process group, and discards raw child output. It requires no host install. The shallow-tag clone is capped at ten minutes, with no retry:

```sh
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261003-v2
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261003-v2/source
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261003-v2/output
/private/tmp/wp5-owner-host-bounded.py 600 \
  git -c credential.helper= clone --filter=blob:none --depth 1 --no-checkout --branch 26.7.4 \
  https://github.com/keycloak/keycloak.git \
  /private/tmp/wp5-as-observer-build-20261003-v2/source
/private/tmp/wp5-owner-host-bounded.py 120 \
  git -C /private/tmp/wp5-as-observer-build-20261003-v2/source checkout --detach \
  aa9fe3fba0c6cd5770f19a49378c55f4378cf544
git -C /private/tmp/wp5-as-observer-build-20261003-v2/source rev-parse HEAD
git -C /private/tmp/wp5-as-observer-build-20261003-v2/source status --porcelain --untracked-files=all
python3 tests/harness/wp5_observer/patch_keycloak_source.py \
  /private/tmp/wp5-as-observer-build-20261003-v2/source
```

The pinned base remains cached from v1. Do not pull again in v2. First verify the existing image ID, platform, and repo digest; if any value differs or the image is absent, stop and request a new preview:

```sh
docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}} {{join .RepoDigests ","}}' eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687
test "$(docker image inspect --format '{{.Id}}' eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687)" = sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687)" = linux/arm64
```

Run a read-only base preflight before apt or Maven. It checks exact Ubuntu release, Java/Javac 21, and the tools needed by the pinned wrapper. It uses no network, bind mount, or writable layer other than its private tmpfs:

```sh
docker run --rm --name wp5-as-observer-builder-20261003-v2 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=0700 \
  --entrypoint /bin/sh eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687 -ec '
    . /etc/os-release
    test "$ID:$VERSION_ID" = ubuntu:26.04
    for tool in java javac tar timeout tr dirname basename mktemp mkdir mv rm sort comm dpkg-query apt-get; do command -v "$tool" >/dev/null; done
    case "$(javac --version 2>/dev/null)" in "javac 21."*) ;; *) exit 42 ;; esac
  '
```

Then build the derived tool image from the one-file context. Do not use another JDK or alter apt sources. The Dockerfile bounds `apt-get update` and the Git install to ten minutes each; the entire derived-image build is one attempt with a 20-minute wall limit. Record only the pinned base digest, Ubuntu ID/release, derived image ID, Git version, and package-version inventory count/hash.

```sh
/private/tmp/wp5-owner-host-bounded.py 1200 docker build --pull=false --no-cache --platform linux/arm64/v8 \
  --tag wp5-as-observer-builder:20261003-5a-v2 \
  --file tests/harness/wp5_observer/builder/Dockerfile \
  tests/harness/wp5_observer/builder >/dev/null 2>&1
docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' wp5-as-observer-builder:20261003-5a-v2
```

Before using the derived image, run this isolated preflight with no network, no bind mounts, a read-only root filesystem, and only a 64 MiB private tmpfs. It checks only fixed tool-presence/identity facts and emits no environment, registry, or file contents:

```sh
docker run --rm --name wp5-as-observer-builder-20261003-v2 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=0700 \
  --entrypoint /bin/sh wp5-as-observer-builder:20261003-5a-v2 -c '
    set -eu
    test "$(. /etc/os-release; printf %s "$ID:$VERSION_ID")" = ubuntu:26.04
    for tool in java javac git tar timeout tr dirname basename mktemp mkdir mv rm cp chmod install sort comm dpkg-query; do command -v "$tool" >/dev/null; done
    case "$(javac --version 2>/dev/null)" in "javac 21."*) ;; *) exit 42 ;; esac
    case "$(git --version 2>/dev/null)" in "git version "*) ;; *) exit 43 ;; esac
    test -s /usr/local/share/wp5-added-package-versions.txt
  '
```

After this preflight, run the following network-none invocation. It emits only the Git version and the exact added package/version rows; copy these safe build metadata into the private receipt. Do not emit the full environment or image configuration.

```sh
docker run --rm --name wp5-as-observer-builder-20261003-v2 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=0700 \
  --entrypoint /bin/sh wp5-as-observer-builder:20261003-5a-v2 -ec '
    git --version
    cat /usr/local/share/wp5-added-package-versions.txt
  '
```

If the preflight succeeds, create the dedicated cache volume only after confirming its name is unused:

```sh
docker volume create --label org.picketfence.wp5.phase=observer-build-only \
  --label org.picketfence.wp5.owner=wp5-luna wp5-as-observer-m2-cache-20261003-v2
```

First compile the patched `quarkus/runtime` module and its Maven prerequisites. The pinned Keycloak `quarkus/runtime/pom.xml` owns the helper's package. The exact first compile command is bounded to 20 minutes; output is discarded and only its fixed exit category is returned:

```sh
docker run --rm --name wp5-as-observer-builder-20261003-v2 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network bridge --cpus=4 --memory=8g --pids-limit=512 \
  --tmpfs /tmp:rw,nosuid,nodev,size=2g,mode=0700 \
  --mount type=bind,src=/private/tmp/wp5-as-observer-build-20261003-v2/source,dst=/workspace/source \
  --mount type=bind,src=/private/tmp/wp5-as-observer-build-20261003-v2/output,dst=/workspace/output \
  --mount type=volume,src=wp5-as-observer-m2-cache-20261003-v2,dst=/root/.m2 \
  --workdir /workspace/source --env MAVEN_OPTS=-Xmx4g \
  --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/workspace/source \
  --entrypoint /bin/sh wp5-as-observer-builder:20261003-5a-v2 -c \
  'timeout --signal=TERM --kill-after=30s 20m ./mvnw -ntp -pl quarkus/runtime -am -DskipTests compile >/dev/null 2>&1' >/dev/null 2>&1
```

Only if that compile exits successfully, run Keycloak's documented server-only build with a 45-minute timeout and copy the single expected distribution ZIP to the private output directory with mode 0600:

```sh
docker run --rm --name wp5-as-observer-builder-20261003-v2 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network bridge --cpus=4 --memory=8g --pids-limit=512 \
  --tmpfs /tmp:rw,nosuid,nodev,size=2g,mode=0700 \
  --mount type=bind,src=/private/tmp/wp5-as-observer-build-20261003-v2/source,dst=/workspace/source \
  --mount type=bind,src=/private/tmp/wp5-as-observer-build-20261003-v2/output,dst=/workspace/output \
  --mount type=volume,src=wp5-as-observer-m2-cache-20261003-v2,dst=/root/.m2 \
  --workdir /workspace/source --env MAVEN_OPTS=-Xmx4g \
  --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/workspace/source \
  --entrypoint /bin/sh wp5-as-observer-builder:20261003-5a-v2 -c \
  'timeout --signal=TERM --kill-after=30s 45m ./mvnw -ntp -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install >/dev/null 2>&1 && install -m 0600 quarkus/dist/target/keycloak-26.7.4.zip /workspace/output/keycloak-26.7.4.zip' >/dev/null 2>&1
```

The Maven containers have no published ports, use only the public bridge network while fetching Maven Central/JBoss public dependencies and the wrapper, and receive only the pinned source/output binds plus the named Maven cache volume. One attempt per phase; `timeout`/nonzero exit maps to a fixed phase result without retaining raw output. After the result is recorded, remove only the exact labeled Maven volume and derived builder image after verifying their owner labels. `--rm` removes each named build container. The official base image may remain cached. On success, the patched public source and ZIP remain in the private workspace for review; calculate the ZIP SHA-256 on the host and record it with source commit, handler/helper hashes, base/derived image IDs, Git/package-version metadata, and compile/build exit categories. On failure, remove partial source/output after writing the fixed receipt. Never run broad Docker prune or delete unowned objects. This build-only gate creates no runtime image, pushes no image, and starts no Keycloak service.

## V3 build-only attempt (completed; commands below are historical)

The v3 approval was consumed by one attempt. Pinned-source verification, the Git-only derived builder, and tool preflight passed. The `quarkus/runtime` compile exited 1 and was classified `compiler_failure`; the bounded capture identified no failing project, goal, or location, and the cause remains unknown. Its terminal receipt and independent cleanup evidence are listed above. No server distribution phase ran. The command examples in this section document that completed attempt and must not be replayed. This attempt did not cover any Keycloak service, realm import, TLS probe, Gateway fixture, normal environment, or WP5 5b.

The v3 runner is `tests/harness/wp5_observer/build_capture.py`. It uses Python's standard library, starts each fixed command in an owned process group, reads stdout and stderr into memory, and keeps at most 8 MiB combined and 64 KiB per line. It emits counts, hashes, booleans, fixed error/goal categories, and project IDs found in the pinned source's root/profile reactor modules. It never writes or prints raw build lines, URLs, exceptions, or arbitrary project names. A line or total-byte cap, deadline, or process-group permission/termination failure produces a failed safe result; the runner then checks the exact build container name and both owner labels before force-removing it. An unverifiable process group is recorded as `runner_failure`, never as a clean timeout. There is no retry.

The host workspace is `/private/tmp/wp5-as-observer-build-20261003-v3/`, with `source/` and `output/` children. The only build container name is `wp5-as-observer-builder-20261003-v3`; its fixed labels remain `org.picketfence.wp5.owner=wp5-luna` and `org.picketfence.wp5.phase=observer-build-only`. The derived image tag is `wp5-as-observer-builder:20261003-5a-v3`; its Maven cache volume is `wp5-as-observer-m2-cache-20261003-v3`. The mode-0600 top-level intent and terminal receipt are `/private/tmp/wp5-as-observer-build-intent-20261003-v3.json` and `/private/tmp/wp5-as-observer-build-receipt-20261003-v3.json`. Before creating any of these objects or receipt files, verify each exact name/path is absent and confirm the cached base image ID/digest from the v2 record. Do not pull the base again.

Each phase gets one exclusive mode-0600 attempt marker and one exclusive mode-0600 receipt. The exact markers are `/private/tmp/wp5-as-observer-build-attempt-20261003-v3-derived_builder_build.json`, `/private/tmp/wp5-as-observer-build-attempt-20261003-v3-runtime_module_compile.json`, and `/private/tmp/wp5-as-observer-build-attempt-20261003-v3-server_distribution_build.json`. Receipts use the matching `wp5-as-observer-build-receipt-20261003-v3-<phase>.json` paths. An existing marker blocks that phase even if the subprocess never started; an existing or symlink receipt also blocks it. A separate mode-0600 top-level intent/terminal record is created once for the approved attempt and is never overwritten.

The source phase uses the same pinned Keycloak commit and reviewed two-file patch as v2. Clone and checkout use the reviewed host wrapper, which bounds the Git process group and discards its output. Create the parent and both children with mode 0700. Do not include the repository, `.env`, `.generated`, licenses, private keys, certificates, account data, or normal build artifacts in Docker build context or mounts. Verify the exact v3 workspace, image tag, cache volume, build container name, intent/terminal receipts, all three attempt markers, and all three phase receipts are absent before the first write. Verify the retained base image ID, digest, and platform against the immutable v2 build record. The host wrapper and pinned image facts are listed in the private execution review record.

During the approved v3 attempt, the public source was acquired once and patched at the detached pinned commit. These historical commands must not be replayed:

```sh
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261003-v3
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261003-v3/source
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261003-v3/output
/private/tmp/wp5-owner-host-bounded.py 600 \
  git -c credential.helper= clone --filter=blob:none --depth 1 --no-checkout --branch 26.7.4 \
  https://github.com/keycloak/keycloak.git \
  /private/tmp/wp5-as-observer-build-20261003-v3/source
/private/tmp/wp5-owner-host-bounded.py 120 \
  git -C /private/tmp/wp5-as-observer-build-20261003-v3/source checkout --detach \
  aa9fe3fba0c6cd5770f19a49378c55f4378cf544
python3 tests/harness/wp5_observer/patch_keycloak_source.py \
  /private/tmp/wp5-as-observer-build-20261003-v3/source
```

Confirm the base identity without pulling it, then run the network-none base preflight under the exact v3 container name and labels:

```sh
docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}} {{join .RepoDigests ","}}' \
  eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687
test "$(docker image inspect --format '{{.Id}}' eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687)" = \
  sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259
docker run --rm --name wp5-as-observer-builder-20261003-v3 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=0700 \
  --entrypoint /bin/sh \
  eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687 -ec '
    . /etc/os-release
    test "$ID:$VERSION_ID" = ubuntu:26.04
    for tool in java javac tar timeout tr dirname basename mktemp mkdir mv rm sort comm dpkg-query apt-get; do command -v "$tool" >/dev/null; done
    case "$(javac --version 2>/dev/null)" in "javac 21."*) ;; *) exit 42 ;; esac
  '
```

After reviewing the base image identity and network-none base tool preflight, run the derived-image build through the bounded runner. The exact build context remains the one-file Git-only Dockerfile directory. Outer Docker build output and Maven stdout/stderr are captured in memory by the runner; the Dockerfile itself redirects `apt-get` output, so apt-specific messages are not available to the classifier:

```sh
python3 tests/harness/wp5_observer/build_capture.py derived_builder_build
```

Run the derived-image tool preflight with no network, no mounts, and a read-only root filesystem. It must confirm the pinned Ubuntu 26.04/Java 21 toolset and Git package inventory before creating the Maven volume. Then create only the exact v3 volume and run the two build phases in order:

```sh
docker run --rm --name wp5-as-observer-builder-20261003-v3 \
  --label org.picketfence.wp5.owner=wp5-luna \
  --label org.picketfence.wp5.phase=observer-build-only \
  --platform linux/arm64/v8 --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=0700 \
  --entrypoint /bin/sh wp5-as-observer-builder:20261003-5a-v3 -c '
    set -eu
    test "$(. /etc/os-release; printf %s "$ID:$VERSION_ID")" = ubuntu:26.04
    for tool in java javac git tar timeout tr dirname basename mktemp mkdir mv rm cp chmod install sort comm dpkg-query; do command -v "$tool" >/dev/null; done
    case "$(javac --version 2>/dev/null)" in "javac 21."*) ;; *) exit 42 ;; esac
    case "$(git --version 2>/dev/null)" in "git version "*) ;; *) exit 43 ;; esac
    test -s /usr/local/share/wp5-added-package-versions.txt
  '
```

```sh
docker volume create --label org.picketfence.wp5.phase=observer-build-only \
  --label org.picketfence.wp5.owner=wp5-luna wp5-as-observer-m2-cache-20261003-v3
```

```sh
python3 tests/harness/wp5_observer/build_capture.py runtime_module_compile
```

```sh
python3 tests/harness/wp5_observer/build_capture.py server_distribution_build
```

The runner fixes the Maven goals. The compile uses `timeout ... 20m ./mvnw -ntp -pl quarkus/runtime -am -DskipTests compile`; the server phase is permitted only when the compile receipt is a regular mode-0600 file with matching source/helper digests, exit code 0, no timeout/output cap, and complete stdout/stderr capture. It then runs the pinned server-only `clean install` with a 45-minute in-container timeout and copies only the expected ZIP to the private output directory with mode 0600. The host phase bounds are 20 minutes for the derived image, 22 minutes for compile, and 47 minutes for distribution. Maven phases use 4 CPUs, 8 GiB memory, a 4 GiB heap, 512 process limit, and 2 GiB private tmpfs; do not change Docker VM resources. The Maven bridge network is limited to fetching public wrapper/dependency artifacts. The base and derived tool preflights use `--network none`.

After the derived-image phase succeeds, inspect only its image ID/platform/owner labels and the fixed Git version plus added-package count/hash from a network-none container. Create the v3 cache only after confirming its exact name is unused. The runner mounts only the private source/output directories and that cache; it does not mount this repository.

On timeout, nonzero exit, output overflow, or termination failure, the runner creates the safe phase receipt and exact-container cleanup status. Stop; do not repeat the phase. After the receipt is written, remove only the exact labeled Maven volume and derived image after verifying their owner labels and image ID. On failure, remove the v3 source/output workspace after preserving the private receipts. On success, retain the public source and ZIP in their private directories for root's independent source/JAR/hash check and any later separately approved runtime preview; remove only the owned cache, derived image, and build container after review. Keep the pinned Temurin base. No `docker prune`, image pull, normal service, realm, Control Plane, or Terraform operation is in scope.

Cleanup checks the exact label metadata before removing the one volume or image. If Docker returns a mismatch or unavailable metadata, stop and leave the object for review rather than removing it. The exact private workspace is removed only after confirming it is a real directory under `/private/tmp`, not a symlink. `--rm` handles completed run containers; on a timeout or output cap, the runner verifies the exact container name plus both labels before removal. Keep every phase receipt and attempt marker; they are exclusive and immutable.

At v3 time, source-contract tests passed 7/7 and the capture-runner suite passed 12/12. Root's independent source and compile checks completed; v3 source acquisition, derived build, and Java compile did run as recorded above. No distribution build or runtime started.

## Published-JAR image v2 (build/archive review passed; direct runtime later failed)

Root’s read-only analysis used the clean public clone `/private/tmp/wp5-published-artifact-analysis-20261004/keycloak-source`, at Keycloak 26.7.4 commit `aa9fe3fba0c6cd5770f19a49378c55f4378cf544` and verified release ZIP SHA-256 `a286e98b4296d4e75ee88d8527c7cd463b307caa022f088c9f22cffccc741fa1`. Its runtime JAR SHA-256 is `57bda3c01502dc553029f2e96f3b7b79e6e3aefcc33be13f67b0b29a3e693a2c`; it is unsigned, has no versioned handler, and contains no internal Jandex index.

The initial two-source host feasibility compile used JDK 23 and is not the acceptance result. The approved v2 image build compiled both sources successfully with pinned Temurin 21 (`--release 17`, `-proc:none`) against all 471 identity-checked published JARs. Root independently verified the patched runtime JAR SHA-256 `08f93f1069965a2e068652321eda807d220fbc6a62dab8749986c02659545175`, class major 61, unchanged handler ABI, one hook in the correct order, and an archive delta of one replaced handler plus one added helper; 256 other runtime-JAR entries remained byte-identical. The published `generated-bytecode.jar` contains the `RoutingContext` producer and proxy, and Keycloak’s `QuarkusHttpRequest` source uses the same CDI lookup. This v2 build review preceded the failed v1/v2 runtime attempts; corrected v3 direct runtime results are recorded above. Root evidence: `.generated/evidence/wp5-root-minimal-built-image-review-1791073466967743000.json`.

Root also confirmed that all 471 JARs under the cached pinned Keycloak image's `lib/` tree match the release ZIP inventory. The prepared context contains only the patched handler source, observer source, a 471-entry published-JAR checksum list, its input manifest, the compile script, and the Dockerfile. `prepare_minimal_image_context.py` requires the clean pinned clone and exact ZIP/runtime hashes, creates a new mode-0700 context directory with exclusive mode-0600 files, and refuses an existing output path. It does not copy the clone or ZIP into the Docker context. The Dockerfile compiles the two classes with pinned Temurin 21 (`--release 17`, `-proc:none`), verifies the 471 classpath JAR hashes against the published ZIP and the original runtime JAR digest, checks ABI/hook order and archive-entry changes, then copies only the patched runtime JAR into the pinned Keycloak image. The replacement JAR is installed mode 0644, owner `1000:0`.

That v2 image build established compilation and packaging with pinned JDK 21 only. Subsequent direct-runtime v1/v2 attempts failed their observer gates; the corrected v3 image and direct observer results are recorded above. No stock-Kong fixture was part of those attempts.

## Minimal published-JAR image build (completed; no runtime approval included)

The public-only context was `/private/tmp/wp5-as-peer-minimal-image-build-20261004-v2/context` (seven files, manifest SHA-256 `98f9e8bd88c16415cbd62b0422e01aed7ff6accc8fd56059fe3f3a4d0768eac9`). Preflight verified the absent output tag and exclusive receipt paths, and the cached bases: Keycloak image ID `sha256:dc0f6a6c61f4170f154b6dd89dfc160c839fd24989d2c798af2a7072498bfbac`, digest `sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`; Temurin image ID `sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259`, digest `sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687`. The single-attempt build used the requested `linux/arm64/v8` platform without pulling either base.

The approved command ran exactly once through the existing bounded host wrapper, which discarded child output and emitted only exit code and timeout status. Do not replay it:

```sh
/private/tmp/wp5-owner-host-bounded.py 1200 docker build \
  --pull=false --no-cache --network=none --platform linux/arm64/v8 \
  --tag wp5-as-peer-observer:20261004-minimal-v2 \
  /private/tmp/wp5-as-peer-minimal-image-build-20261004-v2/context
```

The build finished within its 20-minute host deadline, with the Dockerfile javac step bounded at 10 minutes. The existing Docker daemon capacity (4 CPUs / 9.7 GiB) was unchanged. Build `RUN` steps used `--network=none`; `--pull=false` prevented an explicit base pull, and the preflight confirmed both cached pins. No volume, bind mount, Git, APT, Maven, or full-reactor action was used. The wrapper reported exit code 0 and no timeout; raw child output was discarded. The mode-0600 receipt records the context manifest, base IDs/digests, wrapper hash, and image metadata. Image `wp5-as-peer-observer:20261004-minimal-v2` has ID `sha256:a337f1fa03b83468fa7234f11ff507fa57cfff67e1769fcc55676acbdc1618ff`; Docker reports `linux/arm64`, with labels `wp5-luna` / `observer-image-build-only`. Root’s independent archive review passed. Retain this exact image for the later separately approved runtime fixture; the build-only approval is consumed. No broad Docker cleanup was used.

## Full-reactor V4 preview (withdrawn; historical, not executed)

This earlier command plan is retained as history only; do not use it as the next execution plan. Pinned-POM analysis showed internal `maven-plugin` modules bound at `process-classes`, later than `compile`; the official Keycloak guide uses the server `clean install` lifecycle. This build-method concern does not explain the V3 failure.

V4 keeps the single maintained capture runner and adds memory-only ANSI normalization, fail-closed parser completeness, Maven 3 short/fully-qualified goal parsing, and reactor `FAILURE` recognition through canonical project IDs and POM names. Compiler details use fixed categories and bounded counts; only tracked `.java` paths under reactor module `src/` trees are eligible, capped at 32. Unknown output is presence/count only, and parser uncertainty blocks the server-build gate. Compile receipt reads require a regular mode-0600 file. Maven commands add `-B -Dstyle.color=never` for deterministic color suppression ([Maven CLI options](https://maven.apache.org/ref/3.9.16/maven-embedder/cli.html), [Maven CLI source](https://maven.apache.org/ref/3.9.16/maven-embedder/xref/org/apache/maven/cli/MavenCli.html)); lifecycle goals are unchanged.

| Owned item | Exact V4 value |
|---|---|
| Private workspace | `/private/tmp/wp5-as-observer-build-20261004-v4/` (`source/` and `output/`, directories mode 0700) |
| Build container | `wp5-as-observer-builder-20261004-v4` (`--rm`; labels `org.picketfence.wp5.owner=wp5-luna`, `org.picketfence.wp5.phase=observer-build-only`) |
| Derived image | `wp5-as-observer-builder:20261004-5a-v4` |
| Maven cache | `wp5-as-observer-m2-cache-20261004-v4` (owner/phase labels above) |
| Intent / terminal receipt | `/private/tmp/wp5-as-observer-build-intent-20261004-v4.json` / `/private/tmp/wp5-as-observer-build-receipt-20261004-v4.json` |
| Per-phase attempt / receipt | `/private/tmp/wp5-as-observer-build-attempt-20261004-v4-<phase>.json` / `/private/tmp/wp5-as-observer-build-receipt-20261004-v4-<phase>.json`; phases are `derived_builder_build`, `runtime_module_compile`, `server_distribution_build` |

Every exact name and path above must be absent before any V4 write; create the intent, markers, and receipts exclusively at mode 0600 and never overwrite them. Keep the pinned base `eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687` only if its local image ID still equals `sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259` and platform is `linux/arm64/v8`; do not pull it. After acquiring and patching the pinned public source on the host, run the base image network-none preflight under the exact V4 container name/labels with a read-only root and confirm Ubuntu 26.04, Java/Javac 21, and required core tools:

```sh
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261004-v4
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261004-v4/source
install -d -m 0700 /private/tmp/wp5-as-observer-build-20261004-v4/output
/private/tmp/wp5-owner-host-bounded.py 600 \
  git -c credential.helper= clone --filter=blob:none --depth 1 --no-checkout --branch 26.7.4 \
  https://github.com/keycloak/keycloak.git \
  /private/tmp/wp5-as-observer-build-20261004-v4/source
/private/tmp/wp5-owner-host-bounded.py 120 \
  git -C /private/tmp/wp5-as-observer-build-20261004-v4/source checkout --detach \
  aa9fe3fba0c6cd5770f19a49378c55f4378cf544
python3 tests/harness/wp5_observer/patch_keycloak_source.py \
  /private/tmp/wp5-as-observer-build-20261004-v4/source
```

Run the derived-builder build once, inspect its exact local image ID/platform/owner labels, then run the derived image's network-none preflight to confirm the pinned OS/JDK tools plus Git and the exact added package inventory. Create the labeled Maven cache only after that preflight passes:

```sh
python3 tests/harness/wp5_observer/build_capture.py derived_builder_build
docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}} {{.Config.Labels}}' wp5-as-observer-builder:20261004-5a-v4
# Run the derived-image network-none tool/package preflight here.
docker volume create --label org.picketfence.wp5.phase=observer-build-only \
  --label org.picketfence.wp5.owner=wp5-luna wp5-as-observer-m2-cache-20261004-v4
python3 tests/harness/wp5_observer/build_capture.py runtime_module_compile
```

Only after the compile phase receipt passes every success and parser-completeness check may the server distribution phase run, once:

```sh
python3 tests/harness/wp5_observer/build_capture.py server_distribution_build
```

The fixed compile goal is `timeout ... 20m ./mvnw -B -Dstyle.color=never -ntp -pl quarkus/runtime -am -DskipTests compile`; distribution uses the existing pinned server-only `clean install` and copies only `keycloak-26.7.4.zip`. The derived builder is bounded to 20 minutes, compile to 22 minutes host / 20 minutes container, and distribution to 47 minutes host / 45 minutes container. Maven build containers use 4 CPUs, 8 GiB memory, 4 GiB Java heap, 512 processes, 2 GiB private tmpfs, and the runner's fixed source/output/cache mounts; only Maven dependency phases use bridge networking. Never retry a phase or bypass the compile receipt gate. On failure, preserve immutable safe receipts, then remove only the exact owner-labeled V4 container/cache/image and private workspace after verifying identity. On success, retain the public source and ZIP for independent review; after review remove only the exact owned container/cache/image. Keep the pinned base. No Docker prune, normal services, realm, Control Plane, TLS runtime, or WP5 5b is included.

The focused local suites pass 20/20 capture tests and 7/7 observer source-contract tests. Root's independent real-pipe review passed 8/8 against runner SHA `2a90acdef4dad40e979eb211cd71e42a3d3a3923a4f0b26bf975e22981e9c3d4`, with evidence in `.generated/evidence/wp5-root-v4-parser-review-1791068506308463000.json`. These checks validate parser behavior only. V4 source clone, Docker build, compile, and runtime have not run; this preview does not authorize execution.

## v1 isolated direct-observer runtime attempt (historical)

The v1 reviewed run used Compose project `wp5-as-mtls-observer`, one observer Keycloak container, volume `wp5-as-mtls-observer-data`, and host port `127.0.0.1:19443` mapped to container port 8443. It used the retained pinned Keycloak 26.7.4 image with the reviewed runtime JAR and no normal Compose service. The container mounted only the fresh server certificate/key, realm import, and CA trust anchor read-only; all client certificates and keys stayed host-side in a mode-0700 fixture directory with mode-0600 files. `start-dev` used `request` client-auth mode. No host callback, Admin API probe, Gateway, UI, normal `.env`, normal PKI, or Control Plane was used.

The frozen matrix below defined the direct runtime gate. The single run stopped during the expired-client TLS negative before the complete ON log scan and observer-row joins. The repeated-handler runtime trigger is recorded as `not_run`/pending, not demonstrated by this run:

| Probe | Required observation |
|---|---|
| Observer flag OFF | Same image serves fixed positive discovery/JWKS controls and emits no observer record. The no-op path performs no CDI/request/header/peer reads. |
| Observer flag ON | Fixed discovery, JWKS, PAR, token, and revoke method/path requests yield one record per request with an exact 1:1 32-hex ID join. HTTP status remains a separate result. |
| Route A and Route B concurrently | Each operation reports the expected in-memory leaf digest and never shares a correlation ID or certificate result with the other request. |
| No client certificate | With Keycloak `request` mode, an HTTP control reaches Keycloak and reports no peer cert. This is not an mTLS success. |
| Untrusted and expired client certificates | The TLS handshake fails; no HTTP observer row appears. |
| Untrusted server CA and wrong SAN | The client rejects TLS before sending HTTP; no observer row appears. |
| Unknown path, malformed/duplicate correlation header, repeated handler invocation | Unknown paths are not recorded, invalid IDs fail with fixed categories, and repeated handler calls produce at most one record. |

The immutable terminal receipt contains only bounded fixed fields and sanitized operation data; it does not contain the underlying expired-certificate TLS reason. ON logs were not captured or retained after the failed negative, so no observer-row join or complete ON leak scan was verified. Raw TLS errors, observer lines, request/response bodies, headers, certificates, passwords, tokens, and private keys remain absent from the receipt. A missing row, duplicate row, TLS/PKIX disagreement, or log match fails this sub-gate; it does not authorize fallback or 5b.

The failed run receipt initially recorded cleanup pending. Root later verified that the exact project containers, `wp5-as-mtls-observer-data` volume, project network, and port 19443 listener were absent; the fixture image remains retained. After verifying all 17 fixture files and their modes, the host-only fixture directory was removed. The original run, intent, and preparation receipts remain unchanged; the supplemental cleanup receipt records the host removal. No normal service or WP3 state was touched.

The v3 attempt used a fresh v3 fixture and receipts, retained fixed TLS alert/protocol/stage diagnostics, collected a bounded ON scan before cleanup, and removed only the owned project resources and fixture. Root audited these controls and the terminal result. That direct attempt did not measure same-request repeated invocation. The separate re-entry r4 runtime probe has since demonstrated the trigger; its HTTP 401 responses do not establish stock PAR acceptance. No additional direct attempt is authorized by the v3 result.

At the direct-observer v3 checkpoint, full 5a still required a separately reviewed stock Kong 3.16.0.0 Route B fixture for real signed PAR and both logout revoke claims. V15 later satisfied the scoped 5a demo gate recorded above, using the original assertion and the actual observer Keycloak as final TLS peer.

## Current checks

After the corrected raw-path implementation and v3 identity update, `make test-wp5-observer` passed 58/58 and `git diff --check` passed. `make validate` had passed earlier for unchanged infrastructure/configuration inputs. Suite counts were source-contract 7/7, build-capture 20/20, context 6/6, strict observation parser 9/9, and runtime 16/16. Root independently compiled the patched handler/helper against all 471 identity-checked published JARs using JDK 23 `--release 17` and passed 50 path controls; the corrected JDK 21 image build and archive review then passed. Direct-runtime v3 passed 40/40 case gates with 18 positive peer joins, and Root independently audited the terminal receipt/cleanup. Evidence includes `.generated/evidence/wp5-root-minimal-built-image-review-1791083985580572000.json`, `.generated/evidence/wp5-root-direct-terminal-review-1791085120188078000.json`, and the v3 receipts above. The direct AS-peer observer sub-gate passed. The separate re-entry r4 runtime probe was accepted: canonical observer row counts were `[1, 1, 0]`, re-entry counts were `[[], [2, 3, 4], []]`, and its probe-enabled row joined to the valid Route B peer. This earlier check summary predates the v15 stock fixture; its accepted 5a result is recorded above.
