# FAPI 2.0 design package

## Current target: 3rd Party via API Gateway (proposed)

- [3rd Party経由FAPI 2.0デモ要件](third-party-fapi2-requirements.md): implementation contract for the 3rd Party topology. It amends the v1 requirements below.
- [3rd PartyとAPI GatewayのFAPI 2.0必須要件](third-party-fapi2-conformance.md): implementation-agnostic FAPI 2.0 client and resource server requirements, mapped to Kong Gateway 3.16.
- [Delivery plan](third-party-delivery-plan.md): work packages (Issue drafts), roles, and verification method.

## v1: direct dual-route demo (implemented on main)

[Keycloak FAPI 2.0 demo requirements](fapi2-keycloak-requirements.md) defines the v1 implementation contract and acceptance scenarios. Sections not amended by the 3rd Party requirements still apply.

## Decision records

- [ADR 0009: 3rd Party client gateway topology](../decisions/0009-third-party-client-gateway-topology.md) (proposed)
- [ADR 0010: API Gateway resource server validation](../decisions/0010-api-gateway-resource-server-validation.md) (proposed)
- [ADR 0007: Keycloak-only FAPI 2.0 demo](../decisions/0007-keycloak-only-fapi2-demo.md), amended by ADR 0009
- [ADR 0008: Route B endpoint authentication split](../decisions/0008-route-b-endpoint-auth-split.md)
- [ADR 0006: custom plugin, GHCR, and logout](../decisions/0006-fapi-custom-plugin-ghcr-logout.md), superseded for the Auth0 dependency

## Workflow artifacts

Each diagram ships as a reviewable JSON source, a static PNG, and an interactive HTML artifact under `workflows/`. The interactive artifact is also published to GitHub Pages for link-only sharing.

The local files show the proposed 3rd Party design. The GitHub Pages links still show the v1 diagrams until this design is merged and republished.

| Workflow | Source | Interactive artifact (GitHub Pages, v1) | Local HTML |
|---|---|---|---|
| Architecture: 3rd Party via API Gateway | [JSON](workflows/third-party-architecture.architecture.json) | not yet published | [HTML](workflows/third-party-architecture.architecture.html) |
| Route A: mTLS | [JSON](workflows/route-a-mtls.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/55b6534fdb5b/) | [HTML](workflows/route-a-mtls.workflow.html) |
| Route B: PKJWT + mTLS | [JSON](workflows/route-b-pkj-mtls.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/d4d6f772e970/) | [HTML](workflows/route-b-pkj-mtls.workflow.html) |
| Logout and revocation | [JSON](workflows/logout.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/5522b25c922a/) | [HTML](workflows/logout.workflow.html) |

The diagrams describe workflows, not implementation status. Acceptance depends on the tests in the requirements documents.
