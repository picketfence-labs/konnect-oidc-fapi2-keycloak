# ADR 0017: Build the WP5 test observer from the published Keycloak runtime JAR

- Status: Accepted for test-only image build, fixed raw-path mapping, and direct observer sub-gate; full WP5/5a acceptance remains pending
- Date: 2026-10-04
- Scope: WP5 5a test-only Keycloak peer observer

## Context

The approved v2 and v3 full-reactor attempts both stopped at `quarkus/runtime` compile with exit 1. V3's failure cause is unknown, so those attempts do not establish that the observer source is invalid. Read-only analysis of the pinned 26.7.4 release found the handler in the published runtime JAR, verified a two-source `--release 17` feasibility compile, and confirmed the published classpath JAR inventory matches the cached official image.

The direct TLS fixture v2 attempt passed 39/40 cases but failed the observer row gate: a complete bounded ON scan parsed 22 rows, all `observer_failure` with unknown endpoint/method/path, no correlation ID, and no peer metadata; zero rows joined. Root's offline inspection of the exact published Quarkus 3.33.3.2 JAR confirmed `UriInfoImpl.getPath(false)` throws `IllegalArgumentException` before accessing the request context, and an offline Java call reproduced that exception class. The v2 receipt did not preserve the Java exception class, so the unsupported call is a definite source defect and a source-derived explanation of the rows, not a serialized runtime exception finding.

## Decision

Use the reviewed local, three-stage image build: it takes the released runtime JAR and dependency tree from the digest-pinned Keycloak image, compiles the pinned handler patch and package-private observer with digest-pinned Temurin 21 (`--release 17`, annotation processing disabled), then copies only the patched runtime JAR into the same pinned Keycloak image. Verify input identities, handler ABI and hook order, and that the archive changes only by replacing the handler class and adding the helper. Keep the observer test-only; do not turn this into a published/custom product image.

Read request path only from the already-resolved Vert.x `RoutingContext.request().path()`. Match the exact five absolute `/realms/fapi-demo/...` paths, then store their canonical no-leading-slash forms paired with the fixed HTTP method and endpoint. Do not call `UriInfo.getPath(false)`: the pinned published implementation deterministically rejects encoded-path access before reading the request. Do not read query strings or broaden the path inventory.

The corrected minimal v3 image build succeeded under pinned Temurin 21. Root independently reviewed the actual image archive and bytecode: 471 classpath JARs, 470 unchanged; one replaced handler plus one added helper; 256 other runtime archive entries unchanged; class major 61; handler ABI and hook order unchanged. The patched runtime JAR SHA-256 is `3ef3660cf08ed1ca8b627852a4ddf625e05c18b189680e9bf38e0d9b08b4ded2`, in image `sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953`. Direct TLS fixture v1 and v2 both failed their acceptance gates; the latest v2 scan parsed 22 observer failures with no peer joins. The corrected helper also compiled against all 471 published JARs with host JDK 23 (`--release 17`) and its raw-path inventory passed Root's 50 offline controls. The corrected v3 direct fixture passed 40/40 case gates; Root confirmed 18 positive peer-certificate joins, zero OFF rows, matching eight OFF/ON HTTP baseline statuses, four bounded TLS-negative controls with bracketed checks, a complete bounded log scan, and exact cleanup. Its immutable terminal receipt is `/private/tmp/wp5-as-mtls-observer-run-receipt-20261004-v3.json` (SHA-256 `93f3503abff52ee38449130bc131484664d0c96f8ad35e45b8a6f4924b97709c`), with independent review `.generated/evidence/wp5-root-direct-terminal-review-1791085120188078000.json`. The repeated-handler runtime trigger remains `not_run`; stock-Kong signed PAR and both access-token/refresh-token logout revoke-claim cases remain before full 5a, and 5b is unstarted. This ADR accepts the test-image build method, fixed raw-path source mapping, and direct observer sub-gate only. The V3 full-reactor compile cause remains unknown.

## Consequences

The completed build avoided Git, APT, Maven, and unrelated reactor modules while preserving the exact released runtime/dependency inputs. The resulting image is only an input to a separately reviewed isolated-runtime gate. It does not authorize ordinary Compose services, realm updates, Control Plane changes, Gateway fixtures, or WP5 5b.
