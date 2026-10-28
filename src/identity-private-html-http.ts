import { timingSafeEqual } from "node:crypto";
import type { MembershipRegistry } from "@accountability/identity-policy/membership";
import { createMembershipSessionAuthentication } from "@accountability/identity-policy/membership-session";
import type { HumanSessionProvider } from "@accountability/identity-policy/membership-session";
import { DomainError, invariant, nonempty, requireScope } from "./contracts.ts";
import type { Scope } from "./contracts.ts";
import type { PrivateReleaseStore } from "./store.ts";

export type IdentityPrivateHtmlPolicy = Scope &
  Readonly<{
    origin: string;
    purpose: string;
    ownerIds: readonly string[];
    authenticationTimeoutMs?: number;
    bodyTimeoutMs?: number;
    preparationTimeoutMs?: number;
  }>;
const privateHeaders = {
  "cache-control": "private, no-store",
  pragma: "no-cache",
  vary: "Cookie, Authorization",
  "x-content-type-options": "nosniff",
  "cross-origin-resource-policy": "same-origin",
  "referrer-policy": "no-referrer",
};
const statuses: Readonly<Record<string, number>> = {
  authentication_required: 401,
  authentication_unavailable: 503,
  expired_approval: 409,
  owner_required: 403,
  scope_denied: 403,
  purpose_denied: 403,
  origin_denied: 403,
  csrf_denied: 403,
  route_not_found: 404,
  method_denied: 405,
  invalid_request: 400,
  invalid_input: 400,
  request_aborted: 408,
  body_timeout: 408,
  body_too_large: 413,
  unsupported_media: 415,
  revision_conflict: 409,
  release_not_ready: 409,
};
function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      ...privateHeaders,
      "content-type": "application/json; charset=utf-8",
    },
  });
}
function exact(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  invariant(
    value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Object.keys(value).length === keys.length &&
      keys.every((k) => Object.hasOwn(value, k)),
    "invalid_request",
    "Exact JSON fields required",
  );
  return value as Record<string, unknown>;
}
function revision(value: unknown): number {
  invariant(
    Number.isSafeInteger(value) && (value as number) > 0,
    "invalid_request",
    "Positive viewed revision required",
  );
  return value as number;
}
function text(value: unknown): string {
  nonempty(value, "Identifier", 128);
  return value;
}

async function jsonBody(request: Request, timeoutMs: number): Promise<unknown> {
  invariant(
    /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
      request.headers.get("content-type") ?? "",
    ) && [null, "identity"].includes(request.headers.get("content-encoding")),
    "unsupported_media",
    "Uncompressed JSON required",
  );
  const length = request.headers.get("content-length");
  invariant(
    length === null || (/^\d+$/.test(length) && Number(length) <= 16384),
    "body_too_large",
    "Request body exceeds budget",
  );
  invariant(request.body, "invalid_request", "Body required");
  const reader = request.body.getReader(),
    deadline = performance.now() + timeoutMs;
  function gate() {
    invariant(!request.signal.aborted, "request_aborted", "Request cancelled");
    invariant(
      performance.now() < deadline,
      "body_timeout",
      "Body deadline exceeded",
    );
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  let interrupt = () => {};
  const interrupted = new Promise<never>((_, reject) => {
    interrupt = () =>
      reject(new DomainError("request_aborted", "Request cancelled"));
    request.signal.addEventListener("abort", interrupt, { once: true });
    timer = setTimeout(
      () => reject(new DomainError("body_timeout", "Body deadline exceeded")),
      timeoutMs,
    );
  });
  try {
    invariant(!request.signal.aborted, "request_aborted", "Request cancelled");
    const chunks: Uint8Array[] = [];
    let bytes = 0,
      count = 0;
    while (true) {
      gate();
      const part = await Promise.race([reader.read(), interrupted]);
      gate();
      if (part.done) break;
      count++;
      bytes += part.value.byteLength;
      invariant(
        bytes <= 16384 && count <= 4096,
        "body_too_large",
        "Request body exceeds budget",
      );
      chunks.push(new Uint8Array(part.value));
    }
    let parsed: unknown;
    gate();
    try {
      parsed = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      );
    } catch {
      throw new DomainError("invalid_request", "UTF8 JSON required");
    }
    gate();
    return parsed;
  } finally {
    if (timer) clearTimeout(timer);
    request.signal.removeEventListener("abort", interrupt);
    // A hostile stream cancellation callback must not hold the handler open.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Private human-owner metadata download. Opens no server and authenticates no login itself. */
export function createIdentityPrivateHtmlHandler(
  store: PrivateReleaseStore,
  membership: MembershipRegistry,
  provider: HumanSessionProvider,
  configuration: IdentityPrivateHtmlPolicy,
  clock: () => string,
): (request: Request) => Promise<Response> {
  const policy = structuredClone(configuration),
    prepare = store.exportPrivateHtmlCurrent.bind(store);
  invariant(
    Array.isArray(policy.ownerIds) &&
      policy.ownerIds.length > 0 &&
      policy.ownerIds.length <= 128 &&
      new Set(policy.ownerIds).size === policy.ownerIds.length,
    "invalid_policy",
    "Listed private owners required",
  );
  for (const id of policy.ownerIds) nonempty(id, "Owner", 128);
  const bodyTimeout = policy.bodyTimeoutMs ?? 5000,
    preparationTimeout = policy.preparationTimeoutMs ?? 10000;
  for (const timeout of [bodyTimeout, preparationTimeout])
    invariant(
      Number.isSafeInteger(timeout) && timeout >= 10 && timeout <= 30000,
      "invalid_policy",
      "Bounded timeout required",
    );
  const auth = createMembershipSessionAuthentication(
    membership,
    provider,
    {
      tenantId: policy.tenantId,
      projectId: policy.projectId,
      purpose: policy.purpose,
      origin: policy.origin,
      action: "admin",
      ...(policy.authenticationTimeoutMs === undefined
        ? {}
        : { timeoutMs: policy.authenticationTimeoutMs }),
    },
    clock,
  );
  return async (request) => {
    try {
      const url = new URL(request.url),
        read = url.pathname === "/packaging/session";
      invariant(
        url.origin === policy.origin && !url.username && !url.password,
        "origin_denied",
        "Origin denied",
      );
      invariant(
        read || url.pathname === "/packaging/private-html",
        "route_not_found",
        "Unknown route",
      );
      invariant(
        request.method === (read ? "GET" : "POST"),
        "method_denied",
        "Method denied",
      );
      invariant(
        !url.search && !url.hash,
        "invalid_request",
        "No query or fragment",
      );
      const origin = request.headers.get("origin"),
        site = request.headers.get("sec-fetch-site");
      invariant(
        (origin === null || origin === policy.origin) &&
          (site === null || site === "same-origin") &&
          (read
            ? origin === policy.origin || site === "same-origin"
            : origin === policy.origin),
        "origin_denied",
        "Same origin required",
      );
      invariant(
        !request.signal.aborted,
        "request_aborted",
        "Request cancelled",
      );
      // Capture bounded exact input BEFORE fresh current stored Identity authority.
      let action: { expectedRevision: number; manifestId: string } | null =
        null;
      if (!read) {
        const parsed = exact(await jsonBody(request, bodyTimeout), [
          "expectedRevision",
          "manifestId",
        ]);
        action = {
          expectedRevision: revision(parsed.expectedRevision),
          manifestId: text(parsed.manifestId),
        };
      }
      let identity;
      try {
        identity = await auth.authenticate(
          {
            url: request.url,
            method: request.method,
            headers: new Headers(request.headers),
          },
          request.signal,
        );
      } catch {
        invariant(
          !request.signal.aborted,
          "request_aborted",
          "Request cancelled",
        );
        throw new DomainError(
          "authentication_unavailable",
          "Session unavailable",
        );
      }
      invariant(identity, "authentication_required", "Session required");
      requireScope(identity.context, policy);
      invariant(
        identity.context.purpose === policy.purpose,
        "purpose_denied",
        "Purpose denied",
      );
      invariant(
        identity.context.actor.kind === "human" &&
          identity.context.actor.roles.includes("owner") &&
          policy.ownerIds.includes(identity.context.actor.id),
        "owner_required",
        "Listed human owner required",
      );
      invariant(
        !request.signal.aborted,
        "request_aborted",
        "Request cancelled",
      );
      if (read)
        return json(200, {
          actorId: identity.context.actor.id,
          tenantId: policy.tenantId,
          projectId: policy.projectId,
          csrfToken: identity.csrfToken,
        });
      const csrf = request.headers.get("x-csrf-token") ?? "";
      invariant(
        /^[A-Za-z0-9_-]{32,256}$/.test(csrf) &&
          csrf.length === identity.csrfToken.length &&
          timingSafeEqual(Buffer.from(csrf), Buffer.from(identity.csrfToken)),
        "csrf_denied",
        "Session CSRF required",
      );
      const result = await prepare(
        identity.context,
        action!.expectedRevision,
        action!.manifestId,
        clock,
        { signal: request.signal, timeoutMs: preparationTimeout },
      );
      // The SQL preparation may already be committed. Withholding late bytes does not undo it.
      if (request.signal.aborted)
        return json(503, { error: "preparation_unknown" });
      return new Response(new Uint8Array(result.document.bytes), {
        status: 200,
        headers: {
          ...privateHeaders,
          "content-type": result.document.mediaType,
          "content-disposition": 'attachment; filename="private-metadata.html"',
          "content-security-policy":
            "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          "content-length": String(result.document.bytes.byteLength),
          "x-private-html-sha256": result.document.sha256,
          "x-release-revision": String(result.revision),
          "x-package-hash": result.document.packageHash,
        },
      });
    } catch (error) {
      const code =
        error instanceof DomainError && Object.hasOwn(statuses, error.code)
          ? error.code
          : "preparation_unknown";
      return json(statuses[code] ?? 503, { error: code });
    }
  };
}
