import type { TestContext } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import type { Database } from "@accountability/evidence/database";
import { PrivateReleaseStore } from "../../src/store.ts";
import type { CurrentInputResolver } from "../../src/store.ts";
import type { Artifact, CurrentInputs } from "../../src/index.ts";
import type { Context } from "../../src/contracts.ts";
export const owner: Context = {
  tenantId: "alpha",
  projectId: "study",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "education",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
export const researcher: Context = {
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
export const releasePolicy = {
  tenantId: "alpha",
  projectId: "study",
  ownerIds: ["owner"],
  researcherIds: ["worker"],
};
export async function setup(t: TestContext) {
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
  const store = new PrivateReleaseStore(db, releasePolicy, resolver);
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
export async function approved(store: PrivateReleaseStore) {
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
