# Packaging and correction boundary

Private manifests bind exact artifact editions and hashes, source companions, rights, consent and editorial decision editions, audience and destination. Immutable manifest history preserves proposals, approvals and corrections. Only a listed authenticated human owner can approve or change release policy. External publication is disabled initially; enabling a destination is distinct from approving a particular package.

The gateway rechecks current artifact/decision bindings, policy, owner authority and approval expiry. Upstream decision booleans are trusted adapter results, never form fields or model assertions. Consumers must read current state and attestations in the same protected action transaction. Changing a referenced edition, policy or permission invalidates prior authorization.

A publication handoff consumes the ready state before an external side effect. Unknown delivery stays uncertain and cannot authorize a blind retry. Delivery reconciliation attaches an exact receipt. Corrections invalidate pending manifests and mark attempted or delivered packages as withdrawal-required. Only a separate authenticated gateway receipt confirms withdrawal; prior versions stay in history. This library cannot recall copies already downloaded or force an external provider to remove them.

The library includes private metadata/source-companion exports and an opt-in separate-database private release store; see [durability](DURABILITY.md). The store does not expose external publication or policy enablement and does not claim atomicity across upstream decision services. There is no actual external publisher, binary packaging renderer, binary artifact storage or network transport. Those integrations and live acceptance remain planned. Private export artifacts require the host's ordinary data-access controls. No publication occurs in tests.

Current-input resolver calls use monotonic admission/result gates through callback execution and cloning, plus a timeout timer and signal cleanup. Event-loop blocking cannot make a late result timely. This bounds result acceptance, not blocked JavaScript execution, begun database work or distributed policy changes.

A bounded private HTML metadata formatter now renders the existing prepared export as escaped self-contained review bytes; it is not an authenticated export service or artifact-content packaging/storage. Host fresh authorization/access controls and real-browser/accessibility acceptance remain separate. See PRIVATE_HTML.md.
