import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { MembershipRegistry } from "@accountability/identity-policy/membership";
import {
  privateHtmlResourceId,
  createResourcePrivateHtmlHandler,
} from "../src/identity-private-html-http.ts";
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
  const handler = createResourcePrivateHtmlHandler(
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
const restriction = (manifestId = "package") => ({
  resourceId: privateHtmlResourceId(manifestId),
  memberIds: ["owner"],
  purposes: [owner.purpose],
  actions: ["read" as const],
});
test("resource-aware private download denies missing policy then uses canonical manifest binding in separate owning databases", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.handler(sessionRequest())).status, 200);
  assert.equal((await f.handler(request())).status, 503);
  assert.equal((await f.store.load(owner)).revision, 3);
  await f.membership.setResourcePolicy(owner, 0, restriction(), "allow");
  const response = await f.handler(request());
  assert.equal(response.status, 200);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.equal(
    response.headers.get("x-private-html-sha256"),
    createHash("sha256").update(bytes).digest("hex"),
  );
  assert.equal(response.headers.get("x-release-revision"), "4");
  await scoped(f.db, owner, async (tx) =>
    assert.equal((await tx.list("identity-resource-policy")).length, 0),
  );
  await scoped(f.identityDb, owner, async (tx) => {
    assert.equal((await tx.list("release-control")).length, 0);
    assert(verifyAudit(await tx.audits()));
  });
});
test("current empty policy revokes later byte preparation despite prior successful download", async (t) => {
  const f = await fixture(t);
  await f.membership.setResourcePolicy(owner, 0, restriction(), "allow");
  assert.equal((await f.handler(request())).status, 200);
  await f.membership.setResourcePolicy(
    owner,
    1,
    { ...restriction(), memberIds: [] },
    "revoke",
  );
  assert.equal(
    (await f.handler(request({ ...command, expectedRevision: 4 }))).status,
    503,
  );
  assert.equal((await f.store.load(owner)).revision, 4);
});
test("wrong manifest/purpose/action restrictions and body-supplied resource IDs cannot select another policy", async (t) => {
  const f = await fixture(t);
  await f.membership.setResourcePolicy(
    owner,
    0,
    restriction("other"),
    "wrong-resource",
  );
  assert.equal((await f.handler(request())).status, 503);
  await f.membership.setResourcePolicy(
    owner,
    1,
    { ...restriction(), purposes: ["other"] },
    "wrong-purpose",
  );
  assert.equal((await f.handler(request())).status, 503);
  await f.membership.setResourcePolicy(
    owner,
    2,
    { ...restriction(), actions: ["process"] },
    "wrong-action",
  );
  assert.equal((await f.handler(request())).status, 503);
  assert.equal(
    (
      await f.handler(
        request({ ...command, resourceId: privateHtmlResourceId("other") }),
      )
    ).status,
    400,
  );
  assert.notEqual(
    privateHtmlResourceId("package"),
    privateHtmlResourceId("other"),
  );
  assert.equal((await f.store.load(owner)).revision, 3);
});
