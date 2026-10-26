import { scoped } from "@accountability/evidence/database";
import type { Database, UnitOfWork } from "@accountability/evidence/database";
import {
  canonical,
  digest,
  DomainError,
  invariant,
  requireScope,
} from "./contracts.ts";
import type { Context, Json, Scope } from "./contracts.ts";
import {
  createReleaseState,
  propose,
  approve,
  invalidate,
  preparePrivateExport,
} from "./index.ts";
import type {
  Artifact,
  Binding,
  CurrentInputs,
  ReleaseState,
} from "./index.ts";
export type ReleaseSnapshot = { revision: number; state: ReleaseState };
export type ReleaseStorePolicy = Scope & {
  ownerIds: readonly string[];
  researcherIds: readonly string[];
  resolverTimeoutMs?: number;
};
/** Trusted deployment adapter; receives exact proposed bindings, never intake booleans. */
export type CurrentInputResolver = {
  read(
    context: Context,
    artifacts: readonly Artifact[],
    policyRevision: number,
    signal: AbortSignal,
  ): Promise<CurrentInputs>;
};
export type ReleaseCommand =
  | { type: "propose"; input: Parameters<typeof propose>[2] }
  | { type: "approve"; manifestId: string; expiresAt: string }
  | { type: "invalidate"; cause: Binding; reason: string };
const key = digest({ kind: "private-release-control" });
const json = (v: unknown): Json => JSON.parse(canonical(v)) as Json;
export class PrivateReleaseStore {
  readonly #db: Database;
  readonly #policy: ReleaseStorePolicy;
  readonly #resolve: CurrentInputResolver["read"];
  constructor(
    db: Database,
    policy: ReleaseStorePolicy,
    resolver: CurrentInputResolver,
  ) {
    this.#db = db;
    this.#policy = structuredClone(policy);
    this.#resolve = resolver.read.bind(resolver);
    invariant(
      policy.resolverTimeoutMs === undefined ||
        (Number.isSafeInteger(policy.resolverTimeoutMs) &&
          policy.resolverTimeoutMs >= 10 &&
          policy.resolverTimeoutMs <= 30000),
      "invalid_timeout",
      "Resolver timeout must be 10-30000 milliseconds",
    );
  }
  #guard(c: Context, owner = false) {
    requireScope(c, this.#policy);
    const isOwner =
      c.actor.kind === "human" &&
      c.actor.roles.includes("owner") &&
      this.#policy.ownerIds.includes(c.actor.id);
    invariant(
      isOwner ||
        (!owner &&
          c.actor.roles.includes("researcher") &&
          this.#policy.researcherIds.includes(c.actor.id)),
      owner ? "owner_required" : "access_denied",
      "Registered authenticated release operator required",
    );
  }
  async #get(tx: UnitOfWork): Promise<ReleaseSnapshot> {
    const row = await tx.get<ReleaseState>("release-control", key);
    invariant(row, "not_found", "Release control not found");
    invariant(
      row.value.policy.externalEnabled === false &&
        row.value.policy.allowedDestinations.length === 0,
      "publisher_disabled",
      "This adapter only handles private releases",
    );
    return { revision: row.revision, state: row.value };
  }
  async #current(
    c: Context,
    s: ReleaseState,
    id: string,
  ): Promise<CurrentInputs> {
    const manifest = s.manifests.filter((m) => m.id === id).at(-1);
    invariant(manifest, "not_found", "Manifest not found");
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        Promise.resolve()
          .then(() =>
            this.#resolve(
              structuredClone(c),
              structuredClone(manifest.artifacts),
              s.policy.revision,
              controller.signal,
            ),
          )
          .then((value) => structuredClone(value))
          .catch(() => {
            throw new DomainError(
              "decisions_unavailable",
              "Current decision lookup could not complete",
            );
          }),
        new Promise<CurrentInputs>((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(
              new DomainError(
                "decisions_timeout",
                "Current decision lookup timed out",
              ),
            );
          }, this.#policy.resolverTimeoutMs ?? 5000);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  async create(context: Context, commandId: string): Promise<ReleaseSnapshot> {
    const c = structuredClone(context);
    this.#guard(c, true);
    return scoped(this.#db, c, (tx) =>
      tx.idempotent(
        commandId,
        json({
          type: "create-private-release-control",
          owners: this.#policy.ownerIds,
        }),
        async () => {
          const state = createReleaseState(c, this.#policy.ownerIds);
          const row = await tx.put("release-control", key, 0, state);
          return json({ revision: row.revision, state });
        },
      ),
    ) as Promise<unknown> as Promise<ReleaseSnapshot>;
  }
  async load(context: Context): Promise<ReleaseSnapshot> {
    const c = structuredClone(context);
    this.#guard(c);
    return scoped(this.#db, c, (tx) => this.#get(tx));
  }
  async execute(
    context: Context,
    expectedRevision: number,
    command: ReleaseCommand,
    commandId: string,
  ): Promise<ReleaseSnapshot> {
    const c = structuredClone(context),
      input = structuredClone(command);
    this.#guard(c, input.type === "approve");
    return scoped(this.#db, c, (tx) =>
      tx.idempotent(
        commandId,
        json({ expectedRevision, command: input }),
        async () => {
          const old = await this.#get(tx);
          invariant(
            old.revision === expectedRevision,
            "revision_conflict",
            "Release control revision changed",
          );
          let state: ReleaseState;
          switch (input.type) {
            case "propose":
              invariant(
                input.input.external === false,
                "publisher_disabled",
                "This adapter cannot propose external releases",
              );
              state = propose(c, old.state, input.input);
              break;
            case "approve":
              state = approve(
                c,
                old.state,
                input.manifestId,
                await this.#current(c, old.state, input.manifestId),
                input.expiresAt,
              );
              break;
            case "invalidate":
              state = invalidate(c, old.state, input.cause, input.reason);
              break;
            default:
              throw new DomainError(
                "invalid_command",
                "Unsupported release command",
              );
          }
          if (digest(state) === digest(old.state)) return json(old);
          const row = await tx.put(
            "release-control",
            key,
            expectedRevision,
            state,
          );
          await tx.enqueue(
            "private-release.changed",
            json({
              revision: row.revision,
              event: state.events.at(-1)?.type ?? null,
            }),
            digest({ kind: "private-release", revision: row.revision }),
          );
          return json({ revision: row.revision, state });
        },
      ),
    ) as Promise<unknown> as Promise<ReleaseSnapshot>;
  }
  /** Always rechecks current inputs; no replayable export cache or external transport. */
  async exportPrivate(
    context: Context,
    expectedRevision: number,
    manifestId: string,
  ): Promise<{ revision: number; package: Json }> {
    const c = structuredClone(context);
    this.#guard(c);
    return scoped(this.#db, c, async (tx) => {
      const old = await this.#get(tx);
      invariant(
        old.revision === expectedRevision,
        "revision_conflict",
        "Release control revision changed",
      );
      const current = await this.#current(c, old.state, manifestId);
      const output = preparePrivateExport(c, old.state, manifestId, current);
      const row = await tx.put(
        "release-control",
        key,
        expectedRevision,
        old.state,
      );
      await tx.audit(
        "private-release.export_prepared",
        json({
          manifestId,
          revision: row.revision,
          packageHash: digest(output),
        }),
      );
      return { revision: row.revision, package: output };
    });
  }
}
