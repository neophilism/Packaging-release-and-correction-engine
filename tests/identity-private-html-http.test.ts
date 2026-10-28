import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { MembershipRegistry } from "@accountability/identity-policy/membership";
import { createIdentityPrivateHtmlHandler } from "../src/identity-private-html-http.ts";
import type { IdentityPrivateHtmlPolicy } from "../src/identity-private-html-http.ts";
import { PrivateReleaseStore } from "../src/store.ts";
import {
  setup,
  approved,
  owner,
  releasePolicy,
} from "./helpers/private-html.ts";
const origin = "https://private.example";
const csrf = "s".repeat(40);
const configuration: IdentityPrivateHtmlPolicy = {
  tenantId: owner.tenantId,
  projectId: owner.projectId,
  purpose: owner.purpose,
  origin,
  ownerIds: ["owner"],
};
const command = { expectedRevision: 3, manifestId: "package" };
function request(
  body: unknown = command,
  path = "/packaging/private-html",
  headers: Record<string, string> = {},
) {
  return new Request(origin + path, {
    method: "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      "x-csrf-token": csrf,
      ...headers,
    },
    body: JSON.stringify(body),
  });
}
function sessionRequest() {
  return new Request(origin + "/packaging/session", {
    headers: { "sec-fetch-site": "same-origin" },
  });
}
async function fixture(t: test.TestContext) {
  const release = await setup(t);
  await approved(release.store);
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
    "CREATE ROLE identity_test_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO identity_test_login; SET SESSION AUTHORIZATION identity_test_login",
  );
  const identityDb: Database = {
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
  const membership = new MembershipRegistry(
    identityDb,
    { ...owner, bootstrapOwnerIds: ["owner"] },
    () => owner.now,
  );
  await membership.initialize(owner, "initialize");
  await membership.apply(
    owner,
    1,
    { type: "set-member", id: "second", kind: "human", roles: ["owner"] },
    "second",
  );
  let calls = 0;
  const provider = {
    authenticate: async () => {
      calls++;
      return { actorId: "owner", requestId: "host-request", csrfToken: csrf };
    },
  };
  const handler = createIdentityPrivateHtmlHandler(
    release.store,
    membership,
    provider,
    configuration,
    () => owner.now,
  );
  return {
    ...release,
    identityDb,
    membership,
    provider,
    handler,
    get calls() {
      return calls;
    },
    async demote() {
      await membership.apply(
        { ...owner, actor: { ...owner.actor, id: "second" } },
        2,
        { type: "set-member", id: "owner", kind: "human", roles: ["viewer"] },
        "demote",
      );
    },
  };
}
test("actual current Identity session prepares private bytes, binds audit, keeps databases separate and denies demoted replay", async (t) => {
  const f = await fixture(t);
  const session = await f.handler(sessionRequest());
  assert.equal(session.status, 200);
  assert.deepEqual(await session.json(), {
    actorId: "owner",
    tenantId: "alpha",
    projectId: "study",
    csrfToken: csrf,
  });
  const response = await f.handler(request());
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  assert.equal(
    response.headers.get("content-disposition"),
    'attachment; filename="private-metadata.html"',
  );
  assert.match(response.headers.get("content-security-policy")!, /sandbox/);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.equal(response.headers.get("content-length"), String(bytes.length));
  assert.equal(
    response.headers.get("x-private-html-sha256"),
    createHash("sha256").update(bytes).digest("hex"),
  );
  assert.equal(response.headers.get("x-release-revision"), "4");
  assert.match(bytes.toString(), /Fictional short/);
  await scoped(f.db, owner, async (tx) => {
    assert.equal((await tx.list("identity-membership")).length, 0);
    assert.equal((await tx.list("release-control")).length, 1);
    const audits = await tx.audits();
    assert(verifyAudit(audits));
    assert.equal(
      audits.filter((a) => a.type === "private-release.html_prepared").length,
      1,
    );
  });
  await scoped(f.identityDb, owner, async (tx) => {
    assert.equal((await tx.list("release-control")).length, 0);
    assert.equal((await tx.list("identity-membership")).length, 1);
  });
  await f.demote();
  for (const req of [request(), sessionRequest()]) {
    const denied = await f.handler(req);
    assert.equal(denied.status, 503);
    assert.deepEqual(await denied.json(), {
      error: "authentication_unavailable",
    });
  }
  assert.equal((await f.store.load(owner)).revision, 4);
});

test("exact private routes/CSRF/fields and current consent deny without new preparation", async (t) => {
  const f = await fixture(t);
  for (const [req, status] of [
    [request(command, undefined, { "x-csrf-token": "x".repeat(40) }), 403],
    [request(command, undefined, { origin: "https://foreign.example" }), 403],
    [request(command, undefined, { "sec-fetch-site": "cross-site" }), 403],
    [request({ ...command, external: true }), 400],
    [request({ ...command, expectedRevision: 0 }), 400],
    [request(command, "/packaging/publish"), 404],
    [request(command, "/packaging/private-html?q=1"), 400],
    [request(command, undefined, { "content-encoding": "gzip" }), 415],
  ] as const)
    assert.equal((await f.handler(req)).status, status);
  f.setCurrent({ consentAllowed: false });
  assert.equal((await f.handler(request())).status, 409);
  assert.equal((await f.store.load(owner)).revision, 3);
  const audits = await scoped(f.db, owner, (tx) => tx.audits());
  assert.equal(
    audits.filter((a) => a.type === "private-release.html_prepared").length,
    0,
  );
});

test("live clock is sampled after real owning read and after resolver; expired approval rolls back", async (t) => {
  const f = await fixture(t);
  let now = owner.now,
    sawRead = false;
  const hooked: Database = {
    close: async () => {},
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => {
            const result = await q.query<T>(sql, v);
            if (sql.includes("evidence_record") && sql.includes("SELECT")) {
              sawRead = true;
              now = "2026-01-01T00:11:00Z";
            }
            return result;
          },
        }),
      ),
  };
  const store = new PrivateReleaseStore(hooked, releasePolicy, f.resolver);
  await assert.rejects(
    store.exportPrivateHtmlCurrent(owner, 3, "package", () => now),
    { code: "expired_approval" },
  );
  assert(sawRead);
  assert.equal((await f.store.load(owner)).revision, 3);
  now = owner.now;
  const late = new PrivateReleaseStore(f.db, releasePolicy, {
    read: async (...args) => {
      const result = await f.resolver.read(...args);
      now = "2026-01-01T00:11:00Z";
      return result;
    },
  });
  await assert.rejects(
    late.exportPrivateHtmlCurrent(owner, 3, "package", () => now),
    { code: "expired_approval" },
  );
  assert.equal((await f.store.load(owner)).revision, 3);
});

test("body byte/chunk/encoding/deadline limits run before fresh Identity and capture no authority during stalls", async (t) => {
  const f = await fixture(t);
  const handler = createIdentityPrivateHtmlHandler(
    f.store,
    f.membership,
    f.provider,
    { ...configuration, bodyTimeoutMs: 10 },
    () => owner.now,
  );
  assert.equal(
    (await handler(request({ pad: "x".repeat(16385) }))).status,
    413,
  );
  assert.equal(
    (
      await handler(
        new Request(origin + "/packaging/private-html", {
          method: "POST",
          headers: { origin, "content-type": "application/json" },
          body: new Uint8Array([0xff]),
        }),
      )
    ).status,
    400,
  );
  assert.equal(f.calls, 0);
  const response = await handler(
    new Request(origin + "/packaging/private-html", {
      method: "POST",
      headers: { origin, "content-type": "application/json" },
      body: new ReadableStream({ pull() {} }),
      duplex: "half",
    } as RequestInit),
  );
  assert.equal(response.status, 408);
  assert.equal(f.calls, 0);
  let reads = 0;
  const slow = new Request(origin + "/packaging/private-html", {
    method: "POST",
    headers: {
      origin,
      "content-type": "application/json",
      "x-csrf-token": csrf,
    },
    body: new ReadableStream(
      {
        async pull(c) {
          if (reads++ === 0) {
            await f.demote();
            c.enqueue(new TextEncoder().encode(JSON.stringify(command)));
          } else c.close();
        },
      },
      { highWaterMark: 0 },
    ),
    duplex: "half",
  } as RequestInit);
  assert.equal((await f.handler(slow)).status, 503);
  assert.equal((await f.store.load(owner)).revision, 3);
});

function block(ms: number) {
  const end = performance.now() + ms;
  while (performance.now() < end) {}
}

test("lost real preparation COMMIT acknowledgement is unknown; fresh store sees one edition and stale replay conflicts", async (t) => {
  const f = await fixture(t);
  let lose = true;
  const db: Database = {
    close: async () => {},
    transaction: async (fn) => {
      const value = await f.db.transaction(fn);
      if (lose) {
        lose = false;
        throw Error("private driver diagnostic");
      }
      return value;
    },
  };
  const store = new PrivateReleaseStore(db, releasePolicy, f.resolver);
  const handler = createIdentityPrivateHtmlHandler(
    store,
    f.membership,
    f.provider,
    configuration,
    () => owner.now,
  );
  const response = await handler(request());
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "preparation_unknown" });
  const fresh = new PrivateReleaseStore(f.db, releasePolicy, f.resolver);
  assert.equal((await fresh.load(owner)).revision, 4);
  assert.equal((await handler(request())).status, 409);
  const audits = await scoped(f.db, owner, (tx) => tx.audits());
  assert.equal(
    audits.filter((a) => a.type === "private-release.html_prepared").length,
    1,
  );
  assert(verifyAudit(audits));
});

test("failure after actual prepared audit insertion rolls back, while cancellation after COMMIT withholds bytes and preserves history", async (t) => {
  const f = await fixture(t);
  let fail = true;
  const db: Database = {
    close: async () => {},
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => {
            const result = await q.query<T>(sql, v);
            if (
              fail &&
              sql.includes("INSERT INTO public.evidence_audit") &&
              v?.includes("private-release.html_prepared")
            ) {
              fail = false;
              throw Error("secret post-audit diagnostic");
            }
            return result;
          },
        }),
      ),
  };
  const failHandler = createIdentityPrivateHtmlHandler(
    new PrivateReleaseStore(db, releasePolicy, f.resolver),
    f.membership,
    f.provider,
    configuration,
    () => owner.now,
  );
  assert.equal((await failHandler(request())).status, 503);
  assert.equal((await f.store.load(owner)).revision, 3);
  assert.equal(
    (await scoped(f.db, owner, (tx) => tx.audits())).filter(
      (a) => a.type === "private-release.html_prepared",
    ).length,
    0,
  );
  const controller = new AbortController();
  const commitDb: Database = {
    close: async () => {},
    transaction: async (fn) => {
      const value = await f.db.transaction(fn);
      controller.abort();
      return value;
    },
  };
  const handler = createIdentityPrivateHtmlHandler(
    new PrivateReleaseStore(commitDb, releasePolicy, f.resolver),
    f.membership,
    f.provider,
    configuration,
    () => owner.now,
  );
  const req = new Request(request(), { signal: controller.signal });
  const response = await handler(req);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "preparation_unknown" });
  assert.equal((await f.store.load(owner)).revision, 4);
  assert.equal(
    (await scoped(f.db, owner, (tx) => tx.audits())).filter(
      (a) => a.type === "private-release.html_prepared",
    ).length,
    1,
  );
});

test("invalid/regressed/throwing and blocked clocks plus after-render expiry deny without a preparation edition", async (t) => {
  const f = await fixture(t);
  for (const clock of [
    () => "bad",
    () => "2025-01-01T00:00:00Z",
    () => {
      throw Error("secret clock");
    },
  ]) {
    await assert.rejects(
      f.store.exportPrivateHtmlCurrent(owner, 3, "package", clock),
      { code: "invalid_clock", message: "Trusted clock unavailable" },
    );
  }
  let calls = 0;
  await assert.rejects(
    f.store.exportPrivateHtmlCurrent(owner, 3, "package", () => {
      calls++;
      return calls === 3 ? "2026-01-01T00:11:00Z" : owner.now;
    }),
    { code: "expired_approval" },
  );
  assert.equal(calls, 3);
  await assert.rejects(
    f.store.exportPrivateHtmlCurrent(
      owner,
      3,
      "package",
      () => {
        block(30);
        return owner.now;
      },
      { timeoutMs: 10 },
    ),
    { code: "preparation_interrupted" },
  );
  assert.equal((await f.store.load(owner)).revision, 3);
});

test("cancelled or late current-input work rolls back before write, including already aborted entry", async (t) => {
  const f = await fixture(t),
    controller = new AbortController();
  const store = new PrivateReleaseStore(f.db, releasePolicy, {
    read: async (...args) => {
      const result = await f.resolver.read(...args);
      controller.abort();
      return result;
    },
  });
  await assert.rejects(
    store.exportPrivateHtmlCurrent(owner, 3, "package", () => owner.now, {
      signal: controller.signal,
    }),
    { code: "preparation_interrupted" },
  );
  const before = await scoped(f.db, owner, (tx) => tx.audits());
  await assert.rejects(
    f.store.exportPrivateHtmlCurrent(owner, 3, "package", () => owner.now, {
      signal: controller.signal,
    }),
    { code: "preparation_interrupted" },
  );
  assert.deepEqual(await scoped(f.db, owner, (tx) => tx.audits()), before);
  const late = new PrivateReleaseStore(f.db, releasePolicy, {
    read: async (...args) => {
      const result = await f.resolver.read(...args);
      block(30);
      return result;
    },
  });
  await assert.rejects(
    late.exportPrivateHtmlCurrent(owner, 3, "package", () => owner.now, {
      timeoutMs: 10,
    }),
    { code: "preparation_interrupted" },
  );
  assert.equal((await f.store.load(owner)).revision, 3);
});

test("captured policy/provider/store receiver is stable; listed host owners and independent store policy remain mandatory", async (t) => {
  const f = await fixture(t);
  const config = { ...configuration, ownerIds: ["owner"] };
  const provider = {
    marker: "bound",
    async authenticate() {
      assert.equal(this.marker, "bound");
      return { actorId: "owner", requestId: "host", csrfToken: csrf };
    },
  };
  const store = new PrivateReleaseStore(f.db, releasePolicy, f.resolver);
  const handler = createIdentityPrivateHtmlHandler(
    store,
    f.membership,
    provider,
    config,
    () => owner.now,
  );
  config.ownerIds[0] = "missing";
  config.origin = "https://foreign.example";
  provider.authenticate = async () => {
    throw Error("replaced");
  };
  store.exportPrivateHtmlCurrent = async () => {
    throw Error("replaced store method");
  };
  assert.equal((await handler(request())).status, 200);
  const second = {
    authenticate: async () => ({
      actorId: "second",
      requestId: "host",
      csrfToken: csrf,
    }),
  };
  const notListed = createIdentityPrivateHtmlHandler(
    f.store,
    f.membership,
    second,
    configuration,
    () => owner.now,
  );
  assert.equal((await notListed(sessionRequest())).status, 403);
  const storeDenies = createIdentityPrivateHtmlHandler(
    f.store,
    f.membership,
    second,
    { ...configuration, ownerIds: ["second"] },
    () => owner.now,
  );
  assert.equal(
    (await storeDenies(request({ ...command, expectedRevision: 4 }))).status,
    503,
  );
  assert.equal((await f.store.load(owner)).revision, 4);
});

test("accepted Identity provider bounds late/hung/forged authority, closes signals and leaks no private diagnostics", async (t) => {
  const f = await fixture(t);
  const signals: AbortSignal[] = [];
  for (const provider of [
    {
      authenticate: async (_m: unknown, s: AbortSignal) => {
        signals.push(s);
        block(30);
        return { actorId: "owner", requestId: "r", csrfToken: csrf };
      },
    },
    {
      authenticate: async (_m: unknown, s: AbortSignal) => {
        signals.push(s);
        return new Promise<never>(() => {});
      },
    },
    {
      authenticate: async () => ({
        actorId: "owner",
        requestId: "r",
        csrfToken: csrf,
        roles: ["owner"],
      }),
    },
    {
      authenticate: async () => {
        throw Error("private provider credentials");
      },
    },
  ]) {
    const handler = createIdentityPrivateHtmlHandler(
      f.store,
      f.membership,
      provider,
      { ...configuration, authenticationTimeoutMs: 10 },
      () => owner.now,
    );
    const response = await handler(request());
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      error: "authentication_unavailable",
    });
  }
  assert(signals.every((s) => s.aborted));
  const refusing = createIdentityPrivateHtmlHandler(
    f.store,
    f.membership,
    { authenticate: async () => null },
    configuration,
    () => owner.now,
  );
  assert.equal((await refusing(sessionRequest())).status, 401);
  const aborted = new AbortController();
  aborted.abort();
  assert.equal(
    (await f.handler(new Request(request(), { signal: aborted.signal })))
      .status,
    408,
  );
  assert.equal((await f.store.load(owner)).revision, 3);
});

test("strict body chunk and blocked-JS admission reject before session; active auth cancellation is awaited and fenced", async (t) => {
  const f = await fixture(t);
  let chunks = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        if (chunks++ < 4097) c.enqueue(new Uint8Array());
        else c.close();
      },
    },
    { highWaterMark: 0 },
  );
  const chunkRequest = new Request(origin + "/packaging/private-html", {
    method: "POST",
    headers: { origin, "content-type": "application/json" },
    body,
    duplex: "half",
  } as RequestInit);
  assert.equal((await f.handler(chunkRequest)).status, 413);
  assert.equal(f.calls, 0);
  const short = createIdentityPrivateHtmlHandler(
    f.store,
    f.membership,
    f.provider,
    { ...configuration, bodyTimeoutMs: 10 },
    () => owner.now,
  );
  let pulled = false;
  const blocked = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        if (!pulled) {
          pulled = true;
          block(30);
          c.enqueue(new TextEncoder().encode(JSON.stringify(command)));
        } else c.close();
      },
    },
    { highWaterMark: 0 },
  );
  const blockedRequest = new Request(origin + "/packaging/private-html", {
    method: "POST",
    headers: { origin, "content-type": "application/json" },
    body: blocked,
    duplex: "half",
  } as RequestInit);
  assert.equal((await short(blockedRequest)).status, 408);
  assert.equal(f.calls, 0);
  const controller = new AbortController();
  let providerSignal: AbortSignal | undefined;
  const handler = createIdentityPrivateHtmlHandler(
    f.store,
    f.membership,
    {
      authenticate: async (_m, s) => {
        providerSignal = s;
        controller.abort();
        return { actorId: "owner", requestId: "r", csrfToken: csrf };
      },
    },
    configuration,
    () => owner.now,
  );
  assert.equal(
    (await handler(new Request(request(), { signal: controller.signal })))
      .status,
    408,
  );
  assert(providerSignal?.aborted);
  assert.equal((await f.store.load(owner)).revision, 3);
});
