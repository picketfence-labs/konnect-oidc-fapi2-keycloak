# FAPI 2.0 design package

## Current target: customer demonstration via 3rd Party (design accepted)

Demonstrate mTLS and private_key_jwt, not full FAPI 2.0 compliance. DP0 selects a dedicated AS transport decorator and a limited bridge signer delegate; the design was reviewed and merged in PR #5. Implementation and runtime acceptance remain pending.

- [DP0: AS mTLS補完契約](third-party-as-mtls-transport.md): fixed-version findings, selected interfaces, identities, and WP5 evidence contract. Not runtime acceptance.

- [お客様向けデモ: 対応範囲と追加実装](third-party-demo-explainer.md): customer-facing explanation of stock features, custom extensions, and gaps.

- [3rd Party経由FAPI 2.0デモ要件](third-party-fapi2-requirements.md): implementation contract for the 3rd Party topology. It amends the v1 requirements below.
- [FAPI 2.0要件と顧客向けデモ対応範囲](third-party-fapi2-conformance.md): implementation-agnostic FAPI 2.0 client and resource server requirements, mapped to Kong Gateway 3.16, with demo priorities and future work.
- [Delivery plan](third-party-delivery-plan.md): work packages (Issue drafts), roles, and verification method.

- [Luna / High開発移譲契約](third-party-luna-handoff.md): Issue #6〜#12の実装境界、開始条件、受入IDと証跡。schema分担補足はPR #13でレビュー待ち。
- [ADR 0013: schema準備とruntime受入の分担](../decisions/0013-work-package-schema-and-acceptance-boundaries.md): WP1のschema準備とWP5の本体実装を分ける設計補足。

## v1: direct dual-route demo (implemented on main)

[Keycloak FAPI 2.0 demo requirements](fapi2-keycloak-requirements.md) defines the v1 implementation contract and acceptance scenarios. Sections not amended by the 3rd Party requirements still apply.

## Decision records

- [ADR 0012: dedicated AS mTLS transport](../decisions/0012-third-party-as-mtls-transport.md) (accepted in PR #5; DP0 mechanism)

- [ADR 0011: customer demo scope](../decisions/0011-customer-demo-scope.md) (accepted in PR #5; updates ADRs 0009/0010 and the third-party application of ADR 0008)

- [ADR 0009: 3rd Party client gateway topology](../decisions/0009-third-party-client-gateway-topology.md) (accepted in PR #5)
- [ADR 0010: API Gateway resource server validation](../decisions/0010-api-gateway-resource-server-validation.md) (accepted in PR #5)
- [ADR 0007: Keycloak-only FAPI 2.0 demo](../decisions/0007-keycloak-only-fapi2-demo.md), amended by ADR 0009
- [ADR 0008: Route B endpoint authentication split](../decisions/0008-route-b-endpoint-auth-split.md)
- [ADR 0006: custom plugin, GHCR, and logout](../decisions/0006-fapi-custom-plugin-ghcr-logout.md), superseded for the Auth0 dependency

## Workflow artifacts

Each diagram ships as a reviewable JSON source, a static PNG, and an interactive HTML artifact under `workflows/`. The interactive artifact is also published to GitHub Pages for link-only sharing.

The local files show the accepted 3rd Party design. GitHub Pages has not been republished; its links still show the v1 diagrams.

| Workflow | Source | Interactive artifact (GitHub Pages, v1) | Local HTML |
|---|---|---|---|
| Architecture: 3rd Party via API Gateway | [JSON](workflows/third-party-architecture.architecture.json) | not yet published | [HTML](workflows/third-party-architecture.architecture.html) |
| Route A: mTLS | [JSON](workflows/route-a-mtls.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/55b6534fdb5b/) | [HTML](workflows/route-a-mtls.workflow.html) |
| Route B: PKJWT + mTLS | [JSON](workflows/route-b-pkj-mtls.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/d4d6f772e970/) | [HTML](workflows/route-b-pkj-mtls.workflow.html) |
| Demo logout/reset | [JSON](workflows/logout.workflow.json) | [Pages](https://picketfence-labs.github.io/diagrams/5522b25c922a/) | [HTML](workflows/logout.workflow.html) |

The diagrams describe workflows, not implementation status. Acceptance depends on the tests in the requirements documents.

## Opusレビュー後の補強（2026-10-02）

[Keycloak側peer証跡](third-party-as-peer-evidence.md)に一次観測・相関方法を固定した。WP5冒頭のAS-MTLS-OBS-01が成立してから本体実装へ進む。Gateway別ロード、再送key、JWT条件、Host/SNI、logout失敗時のresetもDP0へ補強。補足の独立差分確認とPR #5のmergeは完了。実行成立は未確認。
