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
