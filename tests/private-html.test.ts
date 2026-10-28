import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  createReleaseState,
  propose,
  approve,
  preparePrivateExport,
} from "../src/index.ts";
import { renderPrivateMetadataHtml } from "../src/private-html.ts";
import type { Context, Json } from "../src/contracts.ts";
const c: Context = {
  tenantId: "fiction",
  projectId: "review",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "review",
  requestId: "request",
  now: "2026-01-01T00:00:00Z",
};
function prepared(label = "Fictional artifact") {
  const bind = (id: string) => ({
    ref: {
      tenantId: c.tenantId,
      projectId: c.projectId,
      kind: "artifact",
      id,
      revision: 1,
    },
    sha256: "a".repeat(64),
  });
  const a = {
    ...bind("artifact"),
    label,
    sourceBindings: [bind("source")],
    visibility: "private" as const,
    rightsDecision: bind("rights"),
    consentDecision: bind("consent"),
    editorialDecision: bind("editorial"),
  };
  const input = {
    artifacts: [a],
    rightsAllowed: true,
    consentAllowed: true,
    editorialApproved: true,
    policyRevision: 1,
  };
  const state = approve(
    c,
    propose(c, createReleaseState(c, ["owner"]), {
      id: "package",
      artifacts: [a],
      audience: "private",
      destination: "private-review",
      external: false,
    }),
    "package",
    input,
    "2026-01-01T00:10:00Z",
  );
  return preparePrivateExport(c, state, "package", input);
}
test("actual domain-prepared metadata renders deterministic exact UTF8 bytes with independent byte hash", () => {
  const p = prepared(),
    before = JSON.stringify(p),
    one = renderPrivateMetadataHtml(p),
    two = renderPrivateMetadataHtml(p);
  assert.equal(one.visibility, "private");
  assert.equal(one.mediaType, "text/html; charset=utf-8");
  assert.deepEqual(one, two);
  assert.equal(
    one.sha256,
    createHash("sha256").update(one.bytes).digest("hex"),
  );
  assert.equal(JSON.stringify(p), before);
  assert.match(
    new TextDecoder().decode(one.bytes),
    /contains no artifact content bytes/,
  );
  one.bytes.fill(0);
  assert.deepEqual(renderPrivateMetadataHtml(p), two);
});
test("markup URLs and Unicode stay literal without active elements links scripts styles or remote dependencies", () => {
  const html = new TextDecoder().decode(
    renderPrivateMetadataHtml(
      prepared(
        '</pre><script>alert("x")</script><img src="https://invalid.example">雪 &',
      ),
    ).bytes,
  );
  assert.ok(!html.includes("<script"));
  assert.ok(!html.includes("<img"));
  assert.ok(!html.includes("<a "));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes("雪"));
  assert.ok(html.includes("&amp;"));
  assert.match(html, /default-src 'none'/);
  assert.match(html, /<caption>/);
  assert.match(html, /scope="col"/);
});
test("changed companion digest external visibility extra fields and oversized data reject", () => {
  const base = prepared() as any;
  for (const p of [
    { ...base, visibility: "public" },
    { ...base, manifestHash: "b".repeat(64) },
    { ...base, sourceCompanion: [] },
    { ...base, credential: "excluded" },
    { ...base, manifest: { ...base.manifest, external: true } },
    { ...base, manifest: { ...base.manifest, id: "x".repeat(524288) } },
  ])
    assert.throws(() => renderPrivateMetadataHtml(p as Json));
});

test("UTF8 input bytes and escaped output expansion are bounded independently", () => {
  const p = prepared() as any;
  assert.throws(
    () =>
      renderPrivateMetadataHtml({
        ...p,
        manifest: { ...p.manifest, reason: "雪".repeat(180000) },
      }),
    { code: "export_too_large" },
  );
  // Reason is intentionally formatter-only hostile metadata, not a domain transition.
  const expanded = {
    ...p,
    manifest: { ...p.manifest, reason: "&".repeat(450000) },
  };
  assert.ok(Buffer.byteLength(JSON.stringify(expanded)) < 524288);
  assert.throws(() => renderPrivateMetadataHtml(expanded), {
    code: "export_too_large",
  });
});
test("invalid JSON profiles fail without returning bytes and canonical key order does not change output", () => {
  for (const p of [
    null,
    [],
    {},
    false,
    { schemaVersion: 1 },
    "private",
  ] as Json[])
    assert.throws(() => renderPrivateMetadataHtml(p));
  const p = prepared() as Record<string, Json>,
    reordered = Object.fromEntries(Object.entries(p).reverse());
  assert.deepEqual(
    renderPrivateMetadataHtml(p),
    renderPrivateMetadataHtml(reordered),
  );
});
