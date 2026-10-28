import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { PrivateReleaseStore } from "../src/store.ts";
import type { CurrentInputResolver } from "../src/store.ts";
import type { Artifact, CurrentInputs } from "../src/index.ts";
import { DomainError } from "../src/contracts.ts";
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

test("late asynchronous resolver results cannot resume a timed-out approval", async (t) => {
  const f = await setup(t);
  await f.store.execute(
    researcher,
    1,
    { type: "propose", input: proposed },
    "proposal",
  );
  let finish!: (v: CurrentInputs) => void, seen: AbortSignal | undefined;
  const late = new PrivateReleaseStore(
    f.db,
    { ...policy, resolverTimeoutMs: 10 },
    {
      read: async (_c, _a, _p, signal) => {
        seen = signal;
        return new Promise((r) => {
          finish = r;
        });
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
      "late",
    ),
    { code: "decisions_timeout" },
  );
  assert.equal(seen?.aborted, true);
  finish(allowedInputs());
  await new Promise((r) => setImmediate(r));
  assert.equal((await f.store.load(owner)).revision, 2);
  await scoped(f.db, owner, async (tx) =>
    assert.ok(verifyAudit(await tx.audits())),
  );
});
test("resolver callback and cloning failures are sanitized and every signal closes including success", async (t) => {
  const f = await setup(t);
  await f.store.execute(
    researcher,
    1,
    { type: "propose", input: proposed },
    "proposal",
  );
  const seen: AbortSignal[] = [];
  for (const mode of ["exception", "clone-failure", "success"]) {
    const store = new PrivateReleaseStore(f.db, policy, {
      read: async (_c, _a, _p, signal) => {
        seen.push(signal);
        if (mode === "exception")
          throw new DomainError(
            "decisions_timeout",
            "secret fixture credential",
          );
        if (mode === "clone-failure")
          return { ...allowedInputs(), bad: () => "secret fixture credential" };
        return allowedInputs();
      },
    });
    const result = store.execute(
      owner,
      2,
      {
        type: "approve",
        manifestId: "package",
        expiresAt: "2026-01-01T00:10:00Z",
      },
      mode,
    );
    if (mode === "success") assert.equal((await result).revision, 3);
    else
      await assert.rejects(result, (e) => {
        assert.equal((e as { code: string }).code, "decisions_unavailable");
        assert.equal(String(e).includes("secret"), false);
        return true;
      });
    assert.equal(seen.at(-1)?.aborted, true);
  }
  assert.equal((await f.store.load(owner)).revision, 3);
});

test("HTML review consumes an actual fresh restricted-database export and later consent denial prevents new rendering",async t=>{
 const f=await setup(t),ready=await approved(f.store);
 const {renderPrivateMetadataHtml}=await import("../src/private-html.ts");
 const output=await f.store.exportPrivate(researcher,ready.revision,"package");
 const rendered=renderPrivateMetadataHtml(output.package);
 assert.equal(rendered.visibility,"private");assert.ok(rendered.bytes.byteLength>0);
 assert.match(new TextDecoder().decode(rendered.bytes),/Fictional short/);
 const after=await f.store.load(researcher);assert.equal(after.revision,output.revision);
 f.setCurrent({consentAllowed:false});let formatted=false;
 await assert.rejects((async()=>{
   const next=await f.store.exportPrivate(researcher,after.revision,"package");
   formatted=true;renderPrivateMetadataHtml(next.package);
 })());
 assert.equal(formatted,false);assert.deepEqual(await f.store.load(researcher),after);
 // Already downloaded bytes remain a historical snapshot, never a current permit.
 assert.ok(rendered.bytes.byteLength>0);
 await scoped(f.db,owner,async tx=>assert.ok(verifyAudit(await tx.audits())));
});

test("durable HTML preparation binds actual bytes hash length profile and release edition in owning audit",async t=>{
 const f=await setup(t),ready=await approved(f.store),before=await f.store.load(researcher);
 const result=await f.store.exportPrivateHtml(researcher,ready.revision,"package");
 const {createHash}=await import("node:crypto");
 assert.equal(result.revision,ready.revision+1);
 assert.equal(result.document.sha256,createHash("sha256").update(result.document.bytes).digest("hex"));
 const after=await f.store.load(researcher);assert.deepEqual(after.state,before.state);
 await scoped(f.db,owner,async tx=>{
  const rows=(await tx.audits()).filter(a=>a.type==="private-release.html_prepared");assert.equal(rows.length,1);
  assert.deepEqual(rows[0]!.payload,{manifestId:"package",revision:result.revision,packageHash:result.document.packageHash,
    htmlSha256:result.document.sha256,byteLength:result.document.bytes.byteLength,mediaType:result.document.mediaType,profile:"private-metadata-html-v1"});
  assert.ok(verifyAudit(await tx.audits()));
 });
});
test("durable HTML rejects stale editions current consent denial and unauthorized scopes before preparation",async t=>{
 const f=await setup(t),ready=await approved(f.store);
 for(const c of [{...researcher,projectId:"other"},{...researcher,actor:{...researcher.actor,roles:[]}}])
  await assert.rejects(f.store.exportPrivateHtml(c,ready.revision,"package"));
 await assert.rejects(f.store.exportPrivateHtml(researcher,ready.revision-1,"package"),{code:"revision_conflict"});
 f.setCurrent({consentAllowed:false});await assert.rejects(f.store.exportPrivateHtml(researcher,ready.revision,"package"));
 assert.equal((await f.store.load(researcher)).revision,ready.revision);
 await scoped(f.db,owner,async tx=>assert.equal((await tx.audits()).filter(a=>a.type==="private-release.html_prepared").length,0));
});

test("HTML preparation audit failure rolls back containing revision and all checked/prepared audits",async t=>{
 const f=await setup(t),ready=await approved(f.store);let hit=false,fail=true;
 const db={...f.db,transaction:<T>(fn:Parameters<typeof f.db.transaction<T>>[0])=>f.db.transaction(q=>fn({query:async <R>(sql:string,v?:unknown[])=>{
  const r=await q.query<R>(sql,v);
  if(fail && sql.includes("INSERT INTO public.evidence_audit") && v?.includes("private-release.html_prepared")){hit=true;fail=false;throw Error("fixture audit failure");}return r;
 }}))};
 const store=new PrivateReleaseStore(db,policy,f.resolver);
 await assert.rejects(store.exportPrivateHtml(researcher,ready.revision,"package"),/fixture audit failure/);assert.equal(hit,true);
 assert.deepEqual(await f.store.load(researcher),ready);
 await scoped(f.db,owner,async tx=>assert.equal((await tx.audits()).filter(a=>a.type.startsWith("private-release.html_")).length,0));
 assert.equal((await store.exportPrivateHtml(researcher,ready.revision,"package")).revision,ready.revision+1);
});
test("lost HTML preparation COMMIT acknowledgement preserves owning history but cannot replay old expected edition",async t=>{
 const f=await setup(t),ready=await approved(f.store);let wrote=false,lost=false;
 const db={...f.db,transaction:async <T>(fn:Parameters<typeof f.db.transaction<T>>[0])=>{
  const result=await f.db.transaction(q=>fn({query:async <R>(sql:string,v?:unknown[])=>{
   const r=await q.query<R>(sql,v);if(sql.includes("INSERT INTO public.evidence_audit")&&v?.includes("private-release.html_prepared"))wrote=true;return r;
  }}));if(wrote&&!lost){lost=true;throw Error("lost HTML COMMIT acknowledgement");}return result;
 }};
 const store=new PrivateReleaseStore(db,policy,f.resolver);
 await assert.rejects(store.exportPrivateHtml(researcher,ready.revision,"package"),/lost HTML COMMIT/);assert.equal(lost,true);
 const fresh=new PrivateReleaseStore(f.db,policy,f.resolver),current=await fresh.load(researcher);
 assert.equal(current.revision,ready.revision+1);assert.deepEqual(current.state,ready.state);
 await assert.rejects(fresh.exportPrivateHtml(researcher,ready.revision,"package"),{code:"revision_conflict"});
 await scoped(f.db,owner,async tx=>{assert.equal((await tx.audits()).filter(a=>a.type==="private-release.html_prepared").length,1);assert.ok(verifyAudit(await tx.audits()));});
});
test("oversized actual private metadata rendering fails before preparation revision and rolls back checked audit",async t=>{
 const f=await setup(t),large={...artifact,sourceBindings:Array.from({length:1600},(_,i)=>binding("source-"+i))};
 f.setCurrent({artifacts:[large]});
 const p=await f.store.execute(researcher,1,{type:"propose",input:{...proposed,artifacts:[large]}},"large-propose");
 const ready=await f.store.execute(owner,p.revision,{type:"approve",manifestId:"package",expiresAt:"2026-01-01T00:10:00Z"},"large-approve");
 await assert.rejects(f.store.exportPrivateHtml(researcher,ready.revision,"package"),{code:"export_too_large"});
 assert.deepEqual(await f.store.load(researcher),ready);
 await scoped(f.db,owner,async tx=>assert.equal((await tx.audits()).filter(a=>a.type.startsWith("private-release.html_")).length,0));
});
test("HTML preparation captures caller/configuration before transaction awaits and returns detached rendered bytes",async t=>{
 const f=await setup(t),ready=await approved(f.store),c=structuredClone(researcher),config=structuredClone(policy);
 let release!:()=>void,enter!:()=>void;const gate=new Promise<void>(r=>release=r),entered=new Promise<void>(r=>enter=r);
 const db={...f.db,transaction:async <T>(fn:Parameters<typeof f.db.transaction<T>>[0])=>{enter();await gate;return f.db.transaction(fn);}};
 const store=new PrivateReleaseStore(db,config,f.resolver),pending=store.exportPrivateHtml(c,ready.revision,"package");
 await entered;(c.actor as unknown as {roles:string[]}).roles=[];config.researcherIds.length=0;release();
 const result=await pending;const hash=result.document.sha256;result.document.bytes.fill(0);
 await scoped(f.db,owner,async tx=>{const a=(await tx.audits()).find(a=>a.type==="private-release.html_prepared")!;assert.equal((a.payload as {htmlSha256:string}).htmlSha256,hash);});
 assert.deepEqual((await f.store.load(researcher)).state,ready.state);
});
