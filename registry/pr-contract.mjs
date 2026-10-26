/**
 * Versioned, machine-readable PR register.
 * Each work unit is explicitly mapped to real GitHub PR numbers; prose is never parsed.
 * GitHub timestamps remain the evidence for merge/closed/open status.
 */
export const STRUCTURED_PR_PATH = 'registry/prs.json';
export const PR_SNAPSHOT_DIRECTORY = 'registry/pr-snapshots';
const positive = n => Number.isSafeInteger(n) && n > 0;
const validTime = t => {
  // GitHub REST emits RFC3339 UTC at second precision (without milliseconds).
  // Accept second precision and 1-3 fractional digits, validating the calendar.
  if (typeof t !== 'string' ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,3})?Z$/.test(t))
    return false;
  const timestamp = Date.parse(t);
  if (!Number.isFinite(timestamp)) return false;
  const normalized = t.replace(/(?:\.([0-9]{1,3}))?Z$/,
    (_match, fraction) => '.' + (fraction || '').padEnd(3, '0') + 'Z');
  return new Date(timestamp).toISOString() === normalized;
};

export function parsePrRegistry(body, repositoryFullName) {
  if (typeof body !== 'string' || Buffer.byteLength(body, 'utf8') > 2000000)
    throw new Error('PR registry body exceeds the size limit.');
  let doc;
  try { doc = JSON.parse(body); }
  catch { throw new Error('PR registry must be valid JSON.'); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) ||
      doc.schemaVersion !== 1 || doc.repository !== repositoryFullName ||
      !positive(doc.roadmapVersion) || !validTime(doc.observedAt) ||
      typeof doc.planVerified !== 'boolean' || Object.hasOwn(doc, 'milestones') || Object.hasOwn(doc, 'redirectTo') ||
      !Array.isArray(doc.units) || doc.units.length > 10000 ||
      !Array.isArray(doc.pullRequests) || doc.pullRequests.length > 2500 ||
      !Number.isSafeInteger(doc.plannedPrCount) || doc.plannedPrCount !== doc.units.length ||
      (doc.planVerified !== (doc.units.length > 0)))
    throw new Error('Invalid repository identity, plan version, total or observation time.');
  const numbers = new Set();
  const prs = doc.pullRequests.map(record => {
    if (!record || typeof record !== 'object' || !positive(record.id) ||
        !positive(record.number) || numbers.has(record.number) ||
        typeof record.title !== 'string' || !record.title.trim() ||
        !['open','closed'].includes(record.state) ||
        record.url !== 'https://github.com/' + doc.repository + '/pull/' + record.number ||
        !validTime(record.createdAt) || !validTime(record.updatedAt) ||
        (record.mergedAt !== null && !validTime(record.mergedAt)) ||
        (record.closedAt !== null && !validTime(record.closedAt)) ||
        (record.state === 'open' && (record.mergedAt !== null || record.closedAt !== null)) ||
        (record.mergedAt !== null && record.state !== 'closed') ||
        (record.mergedAt !== null && Date.parse(record.mergedAt) > Date.parse(doc.observedAt) + 300000) ||
        record.draft !== true && record.draft !== false)
      throw new Error('Invalid, duplicate, or contradictory GitHub PR record.');
    numbers.add(record.number);
    return record;
  });
  const unitIds = new Set();
  const items = doc.units.map((unit, index) => {
    if (!unit || typeof unit !== 'object' || typeof unit.id !== 'string' ||
        !/^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/.test(unit.id) || !/\d/.test(unit.id) ||
        unitIds.has(unit.id) || typeof unit.title !== 'string' ||
        !unit.title.trim() || unit.title.length > 240 ||
        !Array.isArray(unit.prs) || unit.prs.length > 100 ||
        unit.prs.some(n => !positive(n)) || new Set(unit.prs).size !== unit.prs.length ||
        (unit.contributingPrs !== undefined && (!Array.isArray(unit.contributingPrs) ||
          unit.contributingPrs.length > 100 || unit.contributingPrs.some(n => !positive(n)) ||
          new Set(unit.contributingPrs).size !== unit.contributingPrs.length ||
          unit.contributingPrs.some(n => unit.prs.includes(n)))))
      throw new Error('Invalid unit ID, title, or PR references at item ' + (index + 1));
    validateDependencies(unit, doc.repository);
    unitIds.add(unit.id);
    return {
      ordinal:index + 1, sourceItemId:unit.id, title:unit.title.trim(),
      scope:unit.origin === 'addition' || unit.origin === 'added' ? 'addition' : 'original',
      numbers:unit.prs,
      contributions:unit.contributingPrs ?? [],
      priorEvidence:unit.priorEvidencePrs ?? [],
      dependsOn:unit.dependsOn ?? [],
      externalDependencies:unit.externalDependencies ?? [],
      externalPrerequisites:unit.externalPrerequisites ?? [],
      reason:unit.prs.length ? 'Explicit structured registry PR mapping' : null
    };
  });
  validateDependencyGraph(items);
  return {document:doc,items,pullRequests:prs};
}

const validId = value => typeof value === 'string' && /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/.test(value) && /\d/.test(value);
function validateDependencies(unit, repository) {
  const local = unit.dependsOn ?? [];
  const external = unit.externalDependencies ?? [];
  const prerequisites = unit.externalPrerequisites ?? [];
  if (!Array.isArray(local) || local.some(id => !validId(id) || id === unit.id) || new Set(local).size !== local.length)
    throw new Error('Invalid local dependencies for ' + unit.id);
  if (!Array.isArray(external) || external.some(d => !d || typeof d !== 'object' ||
      typeof d.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(d.repository) ||
      d.repository === repository || !validId(d.unitId)) ||
      new Set(external.map(d => d.repository + '#' + d.unitId)).size !== external.length)
    throw new Error('Invalid cross-repository dependencies for ' + unit.id);
  if (!Array.isArray(prerequisites) || prerequisites.some(p => typeof p !== 'string' || !p.trim()) ||
      new Set(prerequisites).size !== prerequisites.length)
    throw new Error('Invalid external prerequisites for ' + unit.id);
  const prior = unit.priorEvidencePrs ?? [];
  if (!Array.isArray(prior) || prior.some(n => !positive(n)) || new Set(prior).size !== prior.length)
    throw new Error('Invalid historical evidence for ' + unit.id);
}
function validateDependencyGraph(items) {
  const pending = new Map(items.map(item => [item.sourceItemId, item.dependsOn.length]));
  const children = new Map();
  for (const item of items) for (const dependency of item.dependsOn) {
    if (!pending.has(dependency)) throw new Error('Unknown local dependency ' + dependency);
    children.set(dependency, [...(children.get(dependency) ?? []), item.sourceItemId]);
  }
  const ready = items.filter(item => !item.dependsOn.length).map(item => item.sourceItemId);
  for (let i = 0; i < ready.length; i++) for (const child of children.get(ready[i]) ?? []) {
    pending.set(child, pending.get(child) - 1);
    if (!pending.get(child)) ready.push(child);
  }
  if (ready.length !== items.length) throw new Error('PR registry contains a dependency cycle');
}

/** Exact stable IDs only; no ordinal, fuzzy title or contribution-to-completion inference. */
export function titleWorkUnitIds(title) {
  const match = title.trim().match(/^([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*?-[A-Z]*\d+)((?:\/(?:[A-Z][A-Z0-9]*-)?\d+)*)(?=$|[:\s—–-])/i);
  if (!match) return [];
  const first = match[1].toUpperCase();
  const prefix = first.slice(0, first.lastIndexOf('-') + 1);
  return [first, ...match[2].split('/').filter(Boolean).map(id => id.includes('-') ? id.toUpperCase() : prefix + id)];
}
export function attachObservedWorkIds(items, observedPullRequests) {
  const assigned = new Map();
  for (const item of items) for (const number of item.numbers) {
    assigned.set(number, [...(assigned.get(number) ?? []), item.sourceItemId]);
  }
  return items.map(item => {
    const excluded = new Set([...(item.contributions ?? []), ...(item.priorEvidence ?? [])]);
    const matches = observedPullRequests.filter(pr => positive(pr.number) && typeof pr.title === 'string' &&
      !excluded.has(pr.number) && (!assigned.has(pr.number) || assigned.get(pr.number).includes(item.sourceItemId)) &&
      titleWorkUnitIds(pr.title).includes(item.sourceItemId));
    // Open follow-ups revoke completion immediately. Closed follow-ups require an
    // explicit mapping; multiple historical title matches cannot imply acceptance.
    const candidates = matches.filter(pr => !item.numbers.includes(pr.number));
    const open = candidates.filter(pr => pr.state === 'open').map(pr => pr.number);
    if (item.numbers.length) return {...item, numbers:[...new Set([...item.numbers, ...open])]};
    if ((item.contributions?.length ?? 0) || (item.priorEvidence?.length ?? 0)) return item;
    if (candidates.length !== 1) return candidates.length ? {...item, ambiguous:true} : item;
    return {...item, numbers:[candidates[0].number], reason:'Exact work-unit ID in live GitHub PR title'};
  });
}
