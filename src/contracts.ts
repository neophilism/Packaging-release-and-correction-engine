import { createHash, randomUUID } from 'node:crypto';
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Scope = Readonly<{ tenantId: string; projectId: string }>;
export type Ref = Scope & Readonly<{ kind: string; id: string; revision: number }>;
export type Actor = Readonly<{ id: string; kind: 'human' | 'agent' | 'service'; roles: readonly string[] }>;
export type Context = Scope & Readonly<{ actor: Actor; purpose: string; requestId: string; now: string }>;
export class DomainError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.name='DomainError'; this.code=code; }
}
export function invariant(condition: unknown, code: string, message: string): asserts condition {
  if (!condition) throw new DomainError(code, message);
}
export function sameScope(a: Scope, b: Scope): boolean { return a.tenantId===b.tenantId && a.projectId===b.projectId; }
export function requireScope(ctx: Scope, resource: Scope): void { invariant(sameScope(ctx, resource), 'scope_denied', 'Resource is outside the authorized scope'); }
export function nonempty(value: unknown, label: string, max=2000): asserts value is string {
  invariant(typeof value==='string' && value.trim().length>0 && value.length<=max, 'invalid_input', `${label} must be non-empty and at most ${max} characters`);
}
export function validTime(value: string): number {
  const n=Date.parse(value); invariant(Number.isFinite(n), 'invalid_time', 'Invalid timestamp'); return n;
}
export function canonical(value: unknown): string {
  if (value===null || typeof value==='string' || typeof value==='boolean') return JSON.stringify(value);
  if (typeof value==='number') { invariant(Number.isFinite(value),'invalid_json','Finite numbers required'); return JSON.stringify(value); }
  if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  invariant(typeof value==='object' && Object.getPrototypeOf(value)===Object.prototype,'invalid_json','Plain JSON required');
  return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
}
export function digest(value: unknown): string { return createHash('sha256').update(canonical(value)).digest('hex'); }
export function hashBytes(bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('hex'); }
export function newId(): string { return randomUUID(); }
export function refKey(ref: Ref): string { return `${ref.kind}:${ref.id}:${ref.revision}`; }
export type AuditEvent = Scope & { id: string; sequence: number; type: string; actorId: string; at: string; requestId: string; payload: Json; previousHash: string; hash: string };
export type Revision<T> = Scope & { id: string; kind: string; revision: number; value: T; createdAt: string; actorId: string };
export type EngineManifest = { id: string; version: string; capabilities: string[]; consumes: string[]; emits: string[] };
export function validateRef(value:unknown):Ref{
 invariant(value!==null&&typeof value==='object'&&!Array.isArray(value),'invalid_reference','Reference object required');
 const r=value as Record<string,unknown>;invariant(Object.keys(r).every(k=>['tenantId','projectId','kind','id','revision'].includes(k)),'invalid_reference','Unknown reference property');
 for(const field of ['tenantId','projectId','kind','id'])nonempty(r[field],field,128);
 invariant(Number.isSafeInteger(r.revision)&&(r.revision as number)>0,'invalid_reference','Positive revision required');return structuredClone(r) as Ref;
}
