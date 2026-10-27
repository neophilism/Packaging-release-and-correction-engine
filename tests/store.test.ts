import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { PrivateReleaseStore } from "../src/store.ts";
import type { CurrentInputResolver } from "../src/store.ts";
import type { Artifact, CurrentInputs } from "../src/index.ts";
import type { Context } from "../src/contracts.ts";
const owner: Context = {
  tenantId: "alpha",
  projectId: "study",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "education",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
const researcher: Context = {
  ...owner,
  actor: { id: "worker", kind: "agent", roles: ["researcher"] },
};
const binding = (id: string) => ({
  ref: {
    tenantId: "alpha",
    projectId: "study",
    kind: "artifact",
    id,
    revision: 1,
  },
  sha256: "a".repeat(64),
});
const artifact: Artifact = {
  ...binding("film"),
  label: "Fictional short",
  sourceBindings: [binding("source")],
  visibility: "private",
  rightsDecision: binding("rights"),
  consentDecision: binding("consent"),
  editorialDecision: binding("review"),
};
const proposed = {
  id: "package",
  artifacts: [artifact],
  audience: "private-review",
  destination: "private-archive",
  external: false,
};
const policy = {
  tenantId: "alpha",
  projectId: "study",
  ownerIds: ["owner"],
  researcherIds: ["worker"],
};
async function setup(t: test.TestContext) {
  const pg = new PGlite();
  await pg.exec(
    await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    ),
  );
  await pg.exec(
    "CREATE ROLE release_test_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO release_test_login; SET SESSION AUTHORIZATION release_test_login",
  );
  const db: Database = {
    transaction: (fn) =>
      pg.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => ({
            rows: (await q.query(sql, v)).rows as T[],
          }),
        }),
      ),
    close: () => pg.close(),
  };
  t.after(() => pg.close());
  let current: CurrentInputs = {
    artifacts: [artifact],
    rightsAllowed: true,
    consentAllowed: true,
    editorialApproved: true,
    policyRevision: 1,
  };
  let reads = 0;
  const resolver: CurrentInputResolver = {
    read: async (c, artifacts, revision) => {
      assert.equal(c.tenantId, "alpha");
      assert.equal(artifacts[0]!.ref.id, "film");
      assert.equal(revision, 1);
      reads++;
      return structuredClone(current);
    },
  };
  const store = new PrivateReleaseStore(db, policy, resolver);
  await store.create(owner, "create");
  return {
    store,
    db,
    resolver,
    get reads() {
      return reads;
    },
    setCurrent: (v: Partial<CurrentInputs>) => {
      current = { ...current, ...v };
    },
  };
}
async function approved(store: PrivateReleaseStore) {
  const p = await store.execute(
    researcher,
    1,
    { type: "propose", input: proposed },
    "propose",
  );
  return store.execute(
    owner,
    p.revision,
    {
      type: "approve",
      manifestId: "package",
      expiresAt: "2026-01-01T00:10:00Z",
    },
    "approve",
  );
}
test("actual migration persists private history exact approvals exports audit and change outbox", async (t) => {
  const { store, db } = await setup(t),
    ready = await approved(store);
  const result = await store.exportPrivate(
    researcher,
    ready.revision,
    "package",
  );
  assert.equal(
    (result.package as { visibility: string }).visibility,
    "private",
  );
  assert.equal(result.revision, 4);
  const loaded = await store.load(researcher);
  assert.equal(loaded.state.manifests.length, 2);
  assert.equal(loaded.state.manifests[0]!.approval, null);
  assert.equal(loaded.state.policy.externalEnabled, false);
  await scoped(db, owner, async (tx) => {
    assert(verifyAudit(await tx.audits()));
    assert.equal((await tx.claim("worker"))?.topic, "private-release.changed");
  });
});
test("current revoked or changed decisions deny export even after prior approval", async (t) => {
  const s = await setup(t),
    ready = await approved(s.store);
  s.setCurrent({ consentAllowed: false });
  await assert.rejects(
    s.store.exportPrivate(researcher, ready.revision, "package"),
    { code: "release_not_ready" },
  );
  assert.equal((await s.store.load(owner)).revision, ready.revision);
  s.setCurrent({
    consentAllowed: true,
    artifacts: [
      {
        ...artifact,
        rightsDecision: {
          ...artifact.rightsDecision,
          ref: { ...artifact.rightsDecision.ref, revision: 2 },
        },
      },
    ],
  });
  await assert.rejects(
    s.store.exportPrivate(researcher, ready.revision, "package"),
    { code: "stale_artifact" },
  );
  assert.equal(s.reads, 3);
});
test("correction invalidates exact dependent source while preserving approved history", async (t) => {
  const { store } = await setup(t),
    ready = await approved(store);
  const fixed = await store.execute(
    researcher,
    ready.revision,
    {
      type: "invalidate",
      cause: binding("source"),
      reason: "Fictional source correction",
    },
    "correction",
  );
  assert.equal(fixed.state.manifests.at(-1)!.state, "invalidated");
  assert.equal(fixed.state.manifests[1]!.state, "approved");
  await assert.rejects(
    store.exportPrivate(researcher, fixed.revision, "package"),
    { code: "not_authorized" },
  );
});
test("replay is exact and stale contenders cannot overwrite approved or corrected state", async (t) => {
  const { store } = await setup(t);
  const command = { type: "propose" as const, input: proposed };
  const old = await store.execute(researcher, 1, command, "proposal");
  assert.deepEqual(
    await store.execute(researcher, 1, command, "proposal"),
    old,
  );
  await assert.rejects(
    store.execute(
      researcher,
      1,
      { type: "propose", input: { ...proposed, id: "other" } },
      "contender",
    ),
    { code: "revision_conflict" },
  );
  await assert.rejects(
    store.execute(
      researcher,
      1,
      { type: "propose", input: { ...proposed, id: "other" } },
      "proposal",
    ),
  );
  assert.equal((await store.load(owner)).state.manifests.length, 1);
});
test("scope registered actors human ownership and disabled external publication fail closed", async (t) => {
  const { store } = await setup(t);
  for (const c of [
    { ...researcher, tenantId: "beta" },
    { ...researcher, projectId: "other" },
    { ...researcher, actor: { ...researcher.actor, id: "unknown" } },
    { ...owner, actor: { ...owner.actor, kind: "agent" as const } },
  ])
    await assert.rejects(store.load(c));
  await assert.rejects(
    store.execute(
      researcher,
      1,
      { type: "propose", input: { ...proposed, external: true } },
      "external",
    ),
    { code: "publisher_disabled" },
  );
  const p = await store.execute(
    researcher,
    1,
    { type: "propose", input: proposed },
    "proposal",
  );
  await assert.rejects(
    store.execute(
      researcher,
      p.revision,
      {
        type: "approve",
        manifestId: "package",
        expiresAt: "2026-01-01T00:10:00Z",
      },
      "forged",
    ),
    { code: "owner_required" },
  );
  await assert.rejects(
    store.execute(
      owner,
      p.revision,
      { type: "enable-publication" } as any,
      "unknown",
    ),
    { code: "invalid_command" },
  );
});
test("truthy decisions unavailability and timeout cannot persist approval or leak provider details", async (t) => {
  const s = await setup(t);
  await s.store.execute(
    researcher,
    1,
    { type: "propose", input: proposed },
    "proposal",
  );
  s.setCurrent({ rightsAllowed: "yes" as any });
  await assert.rejects(
    s.store.execute(
      owner,
      2,
      {
        type: "approve",
        manifestId: "package",
        expiresAt: "2026-01-01T00:10:00Z",
      },
      "truthy",
    ),
    { code: "release_not_ready" },
  );
  const failing = new PrivateReleaseStore(s.db, policy, {
    read: async () => {
      throw new Error("secret access token");
    },
  });
  await assert.rejects(
    failing.execute(
      owner,
      2,
      {
        type: "approve",
        manifestId: "package",
        expiresAt: "2026-01-01T00:10:00Z",
      },
      "failed",
    ),
    (e: any) =>
      e.code === "decisions_unavailable" && !e.message.includes("secret"),
  );
  let aborted = false;
  const blocked = new PrivateReleaseStore(
    s.db,
    { ...policy, resolverTimeoutMs: 10 },
    {
      read: async (_c, _a, _p, signal) => {
        signal.addEventListener("abort", () => {
          aborted = true;
        });
        return new Promise(() => {});
      },
    },
  );
  await assert.rejects(
    blocked.execute(
      owner,
      2,
      {
        type: "approve",
        manifestId: "package",
        expiresAt: "2026-01-01T00:10:00Z",
      },
      "timeout",
    ),
    { code: "decisions_timeout" },
  );
  assert(aborted);
  assert.equal((await s.store.load(owner)).revision, 2);
});
test("caller mutation and lost acknowledgement preserve exact durable proposal", async (t) => {
  const { store, db, resolver } = await setup(t);
  let lose = true;
  const lossy: Database = {
    transaction: async (fn) => {
      const result = await db.transaction(fn);
      if (lose) {
        lose = false;
        throw new Error("lost acknowledgement");
      }
      return result;
    },
    close: async () => {},
  };
  const uncertain = new PrivateReleaseStore(lossy, policy, resolver);
  const c = structuredClone(researcher),
    input = structuredClone(proposed);
  const pending = uncertain.execute(c, 1, { type: "propose", input }, "lossy");
  (c.actor as { id: string }).id = "changed";
  input.artifacts[0]!.label = "changed";
  await assert.rejects(pending, /lost acknowledgement/);
  const loaded = await store.load(owner);
  assert.equal(loaded.state.manifests[0]!.createdBy, "worker");
  assert.equal(
    loaded.state.manifests[0]!.artifacts[0]!.label,
    "Fictional short",
  );
  assert.deepEqual(
    await store.execute(
      researcher,
      1,
      { type: "propose", input: proposed },
      "lossy",
    ),
    loaded,
  );
});

const allowedInputs = (): CurrentInputs => ({
  artifacts: [artifact],
  rightsAllowed: true,
  consentAllowed: true,
  editorialApproved: true,
  policyRevision: 1,
});
test("blocked resolver cannot approve after its monotonic deadline even if the timer cannot run", async (t) => {
  const f = await setup(t);
  await f.store.execute(
    researcher,
    1,
    { type: "propose", input: proposed },
    "proposal",
  );
  const late = new PrivateReleaseStore(
    f.db,
    { ...policy, resolverTimeoutMs: 10 },
    {
      read: async () => {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30);
        return allowedInputs();
      },
    },
  );
  await assert.rejects(
    late.execute(
      owner,
      2,
      {
        type: "approve",
        manifestId: "package",
        expiresAt: "2026-01-01T00:10:00Z",
      },
      "late-approval",
    ),
    { code: "decisions_timeout" },
  );
  assert.equal((await f.store.load(owner)).revision, 2);
});
test("blocked resolver cannot return a prepared private export or commit an export revision after deadline", async (t) => {
  const f = await setup(t),
    ready = await approved(f.store);
  const late = new PrivateReleaseStore(
    f.db,
    { ...policy, resolverTimeoutMs: 10 },
    {
      read: async () => {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30);
        return allowedInputs();
      },
    },
  );
  await assert.rejects(
    late.exportPrivate(researcher, ready.revision, "package"),
    { code: "decisions_timeout" },
  );
  assert.equal((await f.store.load(owner)).revision, ready.revision);
});
