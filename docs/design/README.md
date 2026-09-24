# FAPI 2.0 design package

Start with [Keycloak FAPI 2.0 demo requirements](fapi2-keycloak-requirements.md). It defines the implementation contract and acceptance scenarios.

## Decision records

- [ADR 0007: Keycloak-only FAPI 2.0 demo](../decisions/0007-keycloak-only-fapi2-demo.md)
- [ADR 0006: custom plugin, GHCR, and logout](../decisions/0006-fapi-custom-plugin-ghcr-logout.md), superseded for the Auth0 dependency

## Workflow artifacts

| Workflow | Source | Interactive artifact |
|---|---|---|
| Route A: mTLS | [JSON](workflows/route-a-mtls.workflow.json) | [HTML](workflows/route-a-mtls.workflow.html) |
| Route B: PKJWT + mTLS | [JSON](workflows/route-b-pkj-mtls.workflow.json) | [HTML](workflows/route-b-pkj-mtls.workflow.html) |
| Logout and revocation | [JSON](workflows/logout.workflow.json) | [HTML](workflows/logout.workflow.html) |

The diagrams describe workflows, not implementation status. Acceptance depends on the tests in the requirements document.
