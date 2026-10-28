import { createHash } from "node:crypto";
import { canonical, digest, invariant } from "./contracts.ts";
import type { Json } from "./contracts.ts";
import { manifestHash } from "./index.ts";
import type { Manifest } from "./index.ts";
export type PrivateMetadataHtml = Readonly<{
  mediaType: "text/html; charset=utf-8";
  visibility: "private";
  bytes: Uint8Array;
  sha256: string;
  packageHash: string;
}>;
const escape = (text: string) =>
  text.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
/** Data formatter ONLY. Host must obtain a freshly authorized export; hashes are not authentication. */
export function renderPrivateMetadataHtml(supplied: Json): PrivateMetadataHtml {
  const literal = canonical(supplied);
  invariant(
    Buffer.byteLength(literal, "utf8") <= 524288,
    "export_too_large",
    "Metadata exceeds512KiB",
  );
  const value = JSON.parse(literal) as Record<string, unknown>;
  invariant(
    value &&
      !Array.isArray(value) &&
      Object.keys(value).length === 5 &&
      [
        "schemaVersion",
        "visibility",
        "manifest",
        "manifestHash",
        "sourceCompanion",
      ].every((k) => Object.hasOwn(value, k)) &&
      value.schemaVersion === 1 &&
      value.visibility === "private",
    "invalid_export",
    "Exact private export profile required",
  );
  const m = value.manifest as Manifest;
  invariant(
    m &&
      m.external === false &&
      m.state === "approved" &&
      typeof m.id === "string" &&
      m.id.length > 0 &&
      m.id.length <= 200 &&
      Number.isSafeInteger(m.revision) &&
      m.revision > 0 &&
      Array.isArray(m.artifacts) &&
      m.artifacts.length > 0 &&
      m.artifacts.length <= 1000,
    "invalid_export",
    "Bounded private manifest required",
  );
  invariant(
    value.manifestHash === manifestHash(m) &&
      Array.isArray(value.sourceCompanion) &&
      digest(value.sourceCompanion) ===
        digest(m.artifacts.flatMap((a) => a.sourceBindings)),
    "export_binding_changed",
    "Exact manifest and source companion required",
  );
  const rows = m.artifacts
    .map((a) => {
      invariant(
        typeof a.label === "string" &&
          a.label.length <= 200 &&
          a.visibility === "private",
        "invalid_export",
        "Private literal artifact required",
      );
      return `<tr><th scope="row">${escape(JSON.stringify(a.label))}</th><td><code>${escape(canonical(a.ref))}</code></td><td><code>${escape(a.sha256)}</code></td></tr>`;
    })
    .join("");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'"><title>Private package metadata</title></head><body><main><h1>Private package metadata</h1><p>Historical metadata snapshot. This document is not authorization, a publication receipt or independent evidence verification. It contains no artifact content bytes.</p><h2>Manifest</h2><p><code>${escape(JSON.stringify(m.id))}</code> — revision ${m.revision}</p><p>Manifest hash: <code>${escape(String(value.manifestHash))}</code></p><table><caption>Exact private artifact references; labels are literal JSON strings</caption><thead><tr><th scope="col">Label</th><th scope="col">Reference</th><th scope="col">SHA256</th></tr></thead><tbody>${rows}</tbody></table><h2>Complete metadata and source companion</h2><pre>${escape(literal)}</pre></main></body></html>`;
  const bytes = new TextEncoder().encode(html);
  invariant(
    bytes.byteLength <= 2097152,
    "export_too_large",
    "Rendered metadata exceeds2MiB",
  );
  return {
    mediaType: "text/html; charset=utf-8",
    visibility: "private",
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    packageHash: digest(value),
  };
}
