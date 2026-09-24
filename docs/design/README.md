# FAPI 2.0 design package

Start with [Keycloak FAPI 2.0 demo requirements](fapi2-keycloak-requirements.md). It defines the implementation contract and acceptance scenarios.

## Decision records

- [ADR 0007: Keycloak-only FAPI 2.0 demo](../decisions/0007-keycloak-only-fapi2-demo.md)
- [ADR 0008: Route B endpoint authentication split](../decisions/0008-route-b-endpoint-auth-split.md)
- [ADR 0006: custom plugin, GHCR, and logout](../decisions/0006-fapi-custom-plugin-ghcr-logout.md), superseded for the Auth0 dependency

## Workflow artifacts

Each diagram ships as a reviewable JSON source, a static PNG, and an interactive HTML artifact under `workflows/`. The interactive artifact is also published to GitHub Pages for link-only sharing.

| Workflow | Source | Interactive artifact (GitHub Pages) | Local HTML |
|---|---|---|---|
| Route A: mTLS | [JSON](workflows/route-a-mtls.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/55b6534fdb5b/) | [HTML](workflows/route-a-mtls.workflow.html) |
| Route B: PKJWT + mTLS | [JSON](workflows/route-b-pkj-mtls.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/d4d6f772e970/) | [HTML](workflows/route-b-pkj-mtls.workflow.html) |
| Logout and revocation | [JSON](workflows/logout.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/5522b25c922a/) | [HTML](workflows/logout.workflow.html) |

The diagrams describe workflows, not implementation status. Acceptance depends on the tests in the requirements document.
