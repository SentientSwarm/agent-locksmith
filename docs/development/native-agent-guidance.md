# Protocol-aware agent guidance

The optional-auth `/skill` route passes the existing caller-filtered
`catalog_listing` projection to the renderer. HTTP and native entries keep their
public type/path. Rendering neither materializes credentials nor contacts an
upstream; it adds no authorization decision. Authentication and catalog reads
retain their existing audit/last-used bookkeeping.

Generic sections live in `src/skill_template.md` and `src/skill/*.md`.
`src/skill/personal.rs` selects safe display fields and separates personalized
HTTP recipes from native instructions. Native connections are distinct from
callable tools. Machine consumers use JSON discovery and complete native schemas,
not Markdown parsing. See the [skill reference](../user/agent-integration/skill-reference.md).

## Repeatable verification

Run the usual locked root suite, strict Clippy and format checks. Focused routes
and the actual daemon smoke are also available separately:

```sh
cargo test --locked --test native_skill_test --test skill_test --test skill_guidance_test
cargo test --locked --test native_skill_process_test -- --nocapture
```

The process case reuses the existing daemon/CLI, verified TLS native receiver and
wire helpers. Generic, invalid-auth, personalized skill and discovery reads leave
authority/custody snapshots and upstream receiving counts unchanged. Subsequent
descriptor-driven HTTP and schema-driven native calls establish one effect each;
the native receiver checks merged fixed context and committed admission. A wrong
HTTP route for the native connection creates no additional effect. Fixtures join
on completion. Source tracing separately establishes the absence of credential
materialization; zero receiving counts alone do not prove that property.

The actual-route regressions preserve the native-only/mixed assertions that fail
on the prior name/description-only renderer. Additional tests cover filtering,
activation, empty views, safe text and protocol-specific Codex recipes. Existing
HTTP repair regressions remain applicable. Independent QA authors its public-doc
consumer before inspecting these implementation recipes.

## Delivery limits

This is a guidance correction within planned 3.0.0, with no package bump,
migration, configuration, SDK or native authority change. Rebuild and restart to
serve the new embedded guidance; existing HTTP consumers keep their wire
contract. The controlled smoke does not establish live provider compatibility,
definition-backed activation or complete onboarding. Full AGENT-209 acceptance and the
existing release readiness gates remain separate. Local validation
does not imply integration, tagging or publication.
