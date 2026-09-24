# Keycloak FAPI 2.0二経路デモ要件

## この文書の目的

この文書は、実装担当者が設計判断を再検討せずに開発を開始できるよう、FAPI 2.0二経路デモの要件、境界、受入条件を定義する。実装の正本はこの文書と[ADR 0007](../decisions/0007-keycloak-only-fapi2-demo.md)である。

要件キーワードは次の意味で使用する。

- **MUST**: 受入に必須
- **SHOULD**: 原則必須。逸脱する場合はPRで理由を記録
- **MAY**: 任意

## 目標

同じKong Gateway data planeから2つの独立したbrowser authorization code flowを実行し、token endpoint client authenticationだけを比較できるようにする。

| Route | Client authentication | Sender constraint |
|---|---|---|
| Route A | `tls_client_auth` | mTLS certificate-bound access token |
| Route B | `private_key_jwt` | mTLS certificate-bound access token |

両RouteはKeycloakでユーザーを認証し、PAR、PKCE S256、certificate-bound token、refresh、revocation、logoutを検証する。

## 対象読者

- Kong Gatewayとcustom pluginを実装する開発者
- Keycloak realmとclient policyを構成する開発者
- Terraform、decK、Docker Compose、GitHub Actionsを保守する開発者
- browser E2Eとsecurity negative testをレビューする担当者

## 完成時の利用者体験

1. 利用者はUIでRoute AまたはRoute Bを選択する。
2. KongはKeycloakへPARを送信する。
3. 利用者はKeycloakのlocal demo userでloginする。
4. Kongは選択したRouteのclient authenticationでauthorization codeを交換する。
5. KeycloakはKongのclient certificateへバインドしたaccess tokenとrefresh tokenを返す。
6. Kongは同じcertificateでPoP verifier APIを呼ぶ。
7. UIはclient authentication方式、token `cnf`、TLS certificate thumbprint、department、logical routeを表示する。
8. 利用者がlogoutすると、Kongはrefresh tokenをrevokeし、local sessionとKeycloak SSO sessionを終了する。
9. 利用者は反対側のRouteを新しいsessionで検証できる。

## Target architecture

### Runtime components

| Component | Responsibility |
|---|---|
| Kong Gateway 3.16.0.0 | OIDC RP、PAR、code exchange、session、header設定、upstream mTLS |
| `fapi-client-auth-bridge` custom plugin | Route BのPKJWT生成とmTLS transport併用、入力sanitization |
| Keycloak 26.7.4 | local login、FAPI policy、token発行、revocation、logout |
| PoP verifier API | JWT検証、`cnf`とTLS certificateのbinding検証、sanitized evidence返却 |
| Demo UI | Route選択、login結果、logout、negative testの開始 |
| Konnect control plane | Gateway configuration配布 |

### Container images

- Kong custom image MUST use `kong/kong-gateway:3.16.0.0` as its base.
- Kong custom image MUST publish to `ghcr.io/picketfence-labs/konnect-oidc-header-routing`.
- Keycloak SHOULD pin `quay.io/keycloak/keycloak:26.7.4` by digest.
- PoP verifier SHOULD use a minimal image and run without root privileges.
- Image tags MUST include an immutable Git commit tag. `latest` MAY exist but MUST NOT be used by the acceptance environment.

## Route and Service model

The target Gateway configuration MUST create two path-selected Routes and two Services.

| Route | Path | Service | Session cookie |
|---|---|---|---|
| Route A | `/api/fapi/mtls` | `fapi-mtls-service` | unique Route A cookie name and suffix |
| Route B | `/api/fapi/pkj-mtls` | `fapi-pkj-mtls-service` | unique Route B cookie name and suffix |

Both Services MAY target the same PoP verifier deployment, but each Service MUST reference its own Kong Certificate entity. A Route MUST NOT reuse the other Route's session cookie.

The existing `department` behavior remains in scope:

- Keycloak MUST issue namespaced `department` and `route` claims.
- Kong MUST overwrite inbound `X-Demo-Department` and `X-Demo-Route` from signed claims.
- Header spoofing MUST NOT change the selected logical Upstream.
- `Authorization`, `Cookie`, internal PKJWT transport headers, and private key material MUST NOT reach an echo response or application log.

## Keycloak requirements

### Realm

The implementation MUST provision a dedicated realm, recommended name `fapi-demo`. Realm configuration MUST be declarative and reviewable. Manual Dashboard-only setup does not satisfy acceptance.

The realm MUST provide:

- OIDC discovery
- PAR endpoint
- authorization endpoint
- token endpoint
- revocation endpoint
- end-session endpoint
- JWKS endpoint
- HTTPS with a trusted development CA

### Demo users and claims

Provision at least two generated-password users.

| User role | `department` | `route` |
|---|---|---|
| Sales demo user | `sales` | `sales-route` |
| Engineering demo user | `engineering` | `engineering-route` |

Passwords MUST be generated outside Git and surfaced only through an explicit operator command. Protocol Mappers MUST add the namespaced claims to ID and access tokens.

### FAPI policy

Both clients MUST use the Keycloak `fapi-2-security-profile` client policy or an equivalent explicit policy with the same enforced controls.

The policy MUST enforce:

- authorization code flow
- PAR for every authorization request
- PKCE with `S256`
- confidential client authentication
- authorization code lifetime of no more than 60 seconds
- signed ID tokens
- FAPI-compatible signing algorithms
- sender-constrained access tokens
- refresh token support

This demo targets the FAPI 2.0 Security Profile. FAPI 2.0 Message Signing and certification submission are out of scope.

### Route A client

Recommended client ID: `kong-fapi-mtls`.

The client MUST:

- authenticate with `tls_client_auth` or Keycloak's standards-equivalent X.509 client authenticator
- trust only the Route A client certificate or its issuing CA
- issue mTLS certificate-bound access and refresh tokens
- reject token requests without the registered certificate
- reject token requests using the Route B certificate

### Route B client

Recommended client ID: `kong-fapi-pkj-mtls`.

The client MUST:

- authenticate with `private_key_jwt`
- register only the public key corresponding to Kong's Route B private JWK
- require a FAPI-compatible client assertion algorithm, recommended `PS256`
- require `aud` to equal the Keycloak issuer string
- reject expired assertions and replayed `jti` values
- issue mTLS certificate-bound access and refresh tokens using the Route B TLS certificate
- reject token requests that contain a valid PKJWT but omit the TLS client certificate

### Key material

The implementation MUST use separate key material for these purposes:

- Keycloak server TLS
- Route A client authentication and token binding
- Route B token binding
- Route B PKJWT signing
- PoP verifier server TLS

Private keys MUST NOT enter Git, Terraform state output, decK state, browser responses, or logs. Development certificates MAY be issued from a repository-local CA workflow if generated artifacts stay ignored.

## Kong Gateway requirements

### Route A OpenID Connect configuration

Route A SHOULD use the stock OpenID Connect plugin without custom token request code.

The configuration MUST:

- use Keycloak discovery
- use PAR
- use PKCE S256
- set token endpoint client authentication to `tls_client_auth`
- reference the Route A Certificate entity
- use the mTLS endpoint alias when Keycloak publishes one
- enable session authentication
- use a Route A-specific redirect URI, logout suffix, and session secret

### Route B custom plugin contract

The custom plugin MUST remain a small preprocessor. It MUST NOT implement a new browser session, authorization endpoint, or BFF.

For token and refresh requests, the plugin MUST:

1. Reject or remove client-supplied `client_assertion` and `client_assertion_type` values from query, body, and headers.
2. Generate a new Private Key JWT with `iss = sub = client_id`.
3. Set `aud` to the exact Keycloak issuer string.
4. Generate a cryptographically random, one-time `jti`.
5. Set a lifetime of 60 seconds or less.
6. Sign with the configured FAPI-compatible private JWK.
7. Pass the assertion to the OpenID Connect plugin without exposing it to the upstream application.
8. Reuse the stock OIDC mTLS certificate loading and endpoint transport path.
9. Remove internal transport headers before the protected Service request.

The plugin MUST run before the OpenID Connect plugin. Any cleanup plugin MUST run after authentication and before proxying to the application.

The plugin MUST fail closed when:

- the issuer is missing or differs from discovery
- the private JWK is unavailable
- the TLS certificate is unavailable
- assertion generation fails
- an external request attempts to supply assertion parameters

The plugin MAY reuse `kong.openid-connect.utils` in the pinned Gateway image. Because this is an internal module, tests MUST detect signature or behavior drift during Gateway upgrades.

### Outbound Service mTLS

Each Service MUST present the same certificate used to obtain that Route's bound token. The implementation MUST NOT share a Service entity if sharing prevents Route-specific client certificates.

## PoP verifier API contract

The PoP verifier is part of the security boundary. It MUST:

1. Require a verified TLS client certificate.
2. Validate the JWT signature against Keycloak JWKS.
3. Validate `iss`, `aud`, `exp`, `nbf`, and required scopes.
4. Require `cnf.x5t#S256`.
5. Compute the SHA-256 thumbprint of the TLS peer certificate.
6. Compare both thumbprints using a constant-time comparison.
7. Return `401 invalid_token` when the claim is absent or different.
8. Return only sanitized evidence to the UI.

The response MAY include:

- Route identifier
- client authentication label
- token certificate thumbprint
- TLS peer certificate thumbprint
- `department` and logical `route`
- boolean binding result

The response MUST NOT include raw tokens, cookies, private keys, full certificates, or client assertions.

## Logout and revocation contract

Each Route MUST expose a distinct logout URL.

The logout sequence MUST be:

1. Resolve the Route-specific Kong session.
2. Revoke the refresh token at Keycloak with the Route's client authentication method.
3. Destroy the Kong session and expire the Route-specific cookie.
4. Redirect the browser to Keycloak `end_session_endpoint`.
5. Return the browser to the route selector UI.

If revocation fails, Kong SHOULD continue local and Keycloak logout so the user is not trapped in a session. The implementation MUST log the failure without token values and MUST fail the automated logout acceptance scenario.

A specific confirmation screen is not an acceptance requirement. A valid `id_token_hint` can allow Keycloak to end the session and redirect immediately.

## UI requirements

The UI MUST provide:

- Route A login button
- Route B login button
- logout button for the active Route
- active client authentication method
- `department` and logical route
- token certificate thumbprint
- TLS peer certificate thumbprint
- binding verification result
- clear error output for expected negative tests

The UI MUST NOT store access tokens, refresh tokens, client assertions, or private keys in browser storage.

## Delivery and automation requirements

### Infrastructure as code

- Keycloak realm, clients, roles, users, Protocol Mappers, and client policies MUST be declarative.
- Gateway entities MUST remain in decK state.
- Konnect infrastructure MAY remain in Terraform.
- Auth0 resources MUST be removed from the target dependency graph or isolated behind an optional legacy profile.
- `make validate` MUST remain safe and MUST NOT mutate live systems.
- Apply, sync, image push, and destroy MUST remain explicit commands.

### GHCR

The repository MUST add a GitHub Actions workflow that:

1. Builds the custom Kong image.
2. Runs unit, integration, and static tests.
3. Generates an SBOM.
4. Runs a vulnerability scan with a documented severity policy.
5. Publishes only after tests pass.
6. Uses `packages: write` for GHCR.
7. Publishes an immutable commit tag and records the image digest.

The workflow MUST NOT print secrets or private key material.

## Observability and evidence

The implementation MUST produce evidence that distinguishes the two Routes without exposing credentials.

Required evidence:

- PAR occurs before browser authorization.
- Route A token request presents the Route A certificate and no PKJWT.
- Route B token request presents the Route B certificate and a valid PKJWT.
- Keycloak token contains `cnf.x5t#S256`.
- Protected API receives the same certificate used for token binding.
- Negative requests fail at the expected boundary.
- Logout revokes the refresh token and ends both Kong and Keycloak sessions.

Logs MUST identify the Route and phase. Logs MUST redact token values, cookies, assertions, JWKs, certificate private keys, and authorization codes.

## Acceptance scenarios

### Positive scenarios

| ID | Scenario | Pass condition |
|---|---|---|
| A-PAR-01 | Route A browser login | PAR, PKCE S256, and mTLS client authentication complete |
| A-POP-01 | Route A protected API call | `cnf` equals the Route A TLS peer certificate thumbprint |
| B-PAR-01 | Route B browser login | PAR and PKCE S256 complete |
| B-PKJ-01 | Route B code exchange | Keycloak accepts PS256 PKJWT with issuer audience and one-time `jti` |
| B-POP-01 | Route B protected API call | `cnf` equals the Route B TLS peer certificate thumbprint |
| CLAIM-01 | Sales and engineering login | signed claims drive the expected logical Upstream |
| LOGOUT-A-01 | Route A logout | refresh replay fails, cookie expires, Keycloak session ends |
| LOGOUT-B-01 | Route B logout | refresh replay fails, cookie expires, Keycloak session ends |
| SWITCH-01 | Route switch after logout | the opposite Route starts a new authorization flow |

### Negative scenarios

| ID | Scenario | Expected result |
|---|---|---|
| A-CERT-01 | Route A token request without certificate | Keycloak rejects client authentication |
| A-CERT-02 | Route A token request with Route B certificate | Keycloak rejects client authentication |
| B-AUD-01 | Route B PKJWT with token endpoint URL as `aud` | Keycloak rejects the assertion |
| B-JTI-01 | Replay a Route B assertion | Keycloak rejects the replay |
| B-SPOOF-01 | Browser supplies `client_assertion` | custom plugin rejects or removes the input |
| B-CERT-01 | Valid PKJWT without TLS certificate | Keycloak rejects token issuance |
| POP-01 | Bound token without client certificate | PoP verifier returns `401 invalid_token` |
| POP-02 | Bound token with the other Route's certificate | PoP verifier returns `401 invalid_token` |
| HEADER-01 | Browser spoofs department and route headers | signed claims overwrite both values |
| LEAK-01 | Inspect application response and logs | no token, cookie, assertion, or private key is present |

## Definition of done

Development is complete when:

- every positive and negative scenario passes in automation or has a documented browser evidence procedure
- `make validate` passes from a clean checkout
- `deck diff` shows only intended tagged entities before sync and no diff after sync
- the custom image is available from GHCR by immutable tag and digest
- a fresh environment can generate secrets, start Keycloak, connect the data plane, and run both Routes from documented commands
- logout and Route switching pass for both Routes
- documentation does not claim OpenID Foundation certification

## Out of scope

- production HA and disaster recovery
- production PKI or HSM integration
- Entra ID federation, MFA, or Conditional Access
- Auth0 HRI
- FAPI 2.0 Message Signing
- OpenID Foundation certification submission
- production audit retention
- real customer identities or data

## Delivery sequence

1. Add Keycloak and PoP verifier scaffolding with generated development PKI.
2. Implement Route A and prove mTLS-bound token issuance.
3. Implement the Route B custom plugin and unit tests.
4. Prove Route B PKJWT plus mTLS token binding.
5. Add revocation and logout for both Routes.
6. Add UI evidence and negative tests.
7. Add GHCR build, SBOM, scan, and immutable publish.
8. Update the diagrams only when implementation evidence matches the workflows.

## Workflow diagrams

- [Route A mTLS workflow](workflows/route-a-mtls.workflow.html)
- [Route B PKJWT and mTLS workflow](workflows/route-b-pkj-mtls.workflow.html)
- [Logout and revocation workflow](workflows/logout.workflow.html)

The JSON files beside each HTML artifact are the reviewable diagram source.

## Primary sources

- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0.html)
- [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [Keycloak FAPI support](https://www.keycloak.org/securing-apps/oidc-layers#_fapi-support)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [Kong OpenID Connect plugin](https://developer.konghq.com/plugins/openid-connect/)
