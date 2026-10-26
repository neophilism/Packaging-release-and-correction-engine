# Shared PR registry contract

`registry/prs.json` is the single active machine-readable plan for Boardroom and Engine Room. Both consumers use `registry/pr-contract.mjs`. `registry/roadmap.json` is a retirement notice only; consumers must not follow redirects or parse alternative plan formats.

The version 1 envelope requires `schemaVersion`, exact `repository`, positive `roadmapVersion`, `planVerified`, `plannedPrCount`, `observedAt`, `units`, and `pullRequests`. An unapproved plan has zero units and `planVerified: false`. Never invent units to fill a count or infer PR numbers from ordinal positions.

Each unit has an immutable `id`, `title`, `origin`, and `prs` containing explicit same-repository PR numbers. `contributingPrs` and `priorEvidencePrs` are partial or historical evidence and cannot imply completion. `dependsOn` contains local IDs. `externalDependencies` contains `{repository, unitId}` objects. `externalPrerequisites` preserves unresolved human/external requirements; Boardroom must block those units until verified resolution is recorded in the source. Scope, acceptance, provenance and other project metadata remain on the unit or document.

`pullRequests` is a dated observation, never authority for current GitHub state. Preserve `observedAt` until actual PR observations change. Live GitHub owns open/closed/merged status. Exact unique leading stable IDs may map previously unlinked PRs; ambiguous matches cannot imply completion. Open follow-ups revoke completion. Merged source work is separate from operational acceptance.

Run `node scripts/validate-pr-registry.mjs`. The same CI contract applies to every repository. Update canonical units and the owning project's specification together; never regenerate a second milestone array. Contract changes must be coordinated between both consumers and source repositories.
