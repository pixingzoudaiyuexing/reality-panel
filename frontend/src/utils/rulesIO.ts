/**
 * Rule export/import helpers — extracted from Rules.tsx so the round-trip is
 * unit-testable without mounting the React page.
 *
 * The export format started as a MINIMAL "share export" (`dest[]`,
 * `listen_port`, `name`). vReality-SNI keeps that old shape importable, but new
 * exports also preserve the fields that matter for migration: protocol,
 * transport, SNI, and load-balance strategy.
 *
 * The golden property this module guarantees: a rule exported by `buildExportJSON`
 * ALWAYS round-trips back through `validateImportEntry` + `parseDest` into the
 * same enabled targets (host/port/enabled), for IPv4, IPv6, single-target, and
 * multi-target rules. See `rulesIO.test.ts`.
 */
import type { ForwardRule, RuleTargetInput } from '../api/types';

/** Mirror of Rules.tsx's ruleTargets(): unfold a rule's targets, falling back
 *  to the legacy target_addr/target_port pair when the targets[] array is empty. */
export function ruleTargets(rule: ForwardRule): RuleTargetInput[] {
  const targets = rule.targets?.length
    ? rule.targets.map(t => ({ host: t.host, port: t.port, enabled: t.enabled }))
    : [{ host: rule.target_addr, port: rule.target_port, enabled: true }];
  return targets;
}

/** Wrap a host:port as a dest string, bracketing IPv6 hosts (`[addr]:port`). */
function formatDest(host: string, port: number): string {
  const h = host.trim();
  const isV6 = h.includes(':') && !h.startsWith('[');
  return isV6 ? `[${h}]:${port}` : `${h}:${port}`;
}

/** The minimal export entry shape. */
export interface ExportEntry {
  dest: string[];
  targets?: RuleTargetInput[];
  listen_port: number;
  name: string;
  protocol?: string;
  public_transport?: string;
  sni?: string;
  camouflage_enabled?: boolean;
  load_balance_strategy?: string;
}

/**
 * Build the compact single-line share-export JSON for a set of rules.
 *
 * - Enabled targets only (disabled ones are dropped — they're not active
 *   forwards).
 * - IPv6 hosts are bracketed so the dest parses back unambiguously.
 * - Always emits a JSON ARRAY (even for a single rule) so the output pastes
 *   straight into the import box (which expects `[{...}]`).
 * - Compact (no pretty-print) so it's the one-line shape shown in the import
 *   hint.
 */
export function buildExportJSON(rules: ForwardRule[]): string {
  const simplified: ExportEntry[] = rules.map(r => {
    const targets = ruleTargets(r).map(t => ({
      host: t.host.trim(),
      port: t.port,
      enabled: t.enabled,
    }));
    // `dest` remains the compact, legacy-compatible representation. `targets`
    // preserves disabled targets for current exports without changing old imports.
    const dest = targets.filter(t => t.enabled).map(t => formatDest(t.host, t.port));
    const publicTransport = r.public_transport === 'nginx_sni' || r.node_transport === 'nginx_sni'
      ? 'nginx_sni'
      : 'raw';
    return {
      dest,
      targets,
      listen_port: r.listen_port,
      name: r.name,
      protocol: publicTransport === 'nginx_sni' ? 'tcp' : r.protocol,
      public_transport: publicTransport,
      sni: publicTransport === 'nginx_sni' ? (r.sni?.trim().toLowerCase() || undefined) : undefined,
      camouflage_enabled: r.camouflage_enabled === true,
      load_balance_strategy: r.load_balance_strategy ?? 'first',
    };
  });
  return JSON.stringify(simplified);
}

/** The dest regex: `[ipv6]` or a non-colon host, then `:port`. Exported so
 *  parseDest and validateImportEntry share ONE definition. */
const DEST_RE = /^(\[.+?\]|[^:]+):(\d+)$/;

/** Parse a `host:port` / `[ipv6]:port` dest string into {host, port}, or null
 *  when malformed. Strips the brackets from an IPv6 host. */
export function parseDest(d: string): { host: string; port: number } | null {
  const m = d.match(DEST_RE);
  if (!m) return null;
  const host = m[1].replace(/^\[|\]$/g, '');
  const port = parseInt(m[2], 10);
  if (!host || port < 1 || port > 65535) return null;
  return { host, port };
}

/** The loose entry shape the import box accepts (every field optional, validated
 *  by validateImportEntry before use). */
export interface ImportEntry {
  name?: string;
  listen_port?: number;
  dest?: string[];
  targets?: RuleTargetInput[];
  protocol?: string;
  public_transport?: string;
  node_transport?: string;
  sni?: string;
  camouflage_enabled?: boolean;
  load_balance_strategy?: string;
}

export interface ValidatedImportEntry {
  name: string;
  listen_port: number;
  dest: string[];
  targets?: RuleTargetInput[];
  protocol?: string;
  public_transport?: string;
  sni?: string;
  camouflage_enabled?: boolean;
  load_balance_strategy?: string;
}

export interface ImportedRulePayload {
  name: string;
  listen_port: number;
  protocol: string;
  public_transport: string;
  forward_mode: 'direct';
  route_mode: 'direct';
  load_balance_strategy: string;
  upload_limit_mbps: number;
  download_limit_mbps: number;
  camouflage_enabled: boolean;
  sni?: string;
  device_group_in: number;
  target_addr: string;
  target_port: number;
  targets: RuleTargetInput[];
}

/**
 * Is `x` a plain, non-null object? Guards against the JSON being a bare
 * primitive / null / array at the entry position (e.g. the user pasted `42` or
 * `"[1,2,3]"`). Arrays are objects in JS, so exclude them explicitly — an entry
 * must be a `{...}` record.
 */
export function isImportEntry(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/**
 * Validate a single import entry. Returns a human-readable error string, or
 * null when the entry is well-formed.
 *
 * The input is `unknown` (straight from `JSON.parse`), so EVERY field is
 * runtime-type-checked before its value is inspected — a malformed paste like
 * `{"name": 123, "listen_port": "80", "dest": "1.2.3.4:80"}` must produce a
 * clean "invalid" verdict, NOT a `.trim() is not a function` crash. (The earlier
 * version assumed the fields were already the right type and crashed on
 * wrong-typed JSON.)
 */
export function validateImportEntry(e: unknown): string | null {
  if (!isImportEntry(e)) return 'entry must be an object';
  // name: required, must be a non-empty string after trim.
  const name = e['name'];
  if (typeof name !== 'string' || name.trim() === '') return 'name is required';
  // listen_port: required, must be an integer in the valid range. A numeric
  // string like "80" is rejected (the export emits a real number; accepting
  // strings would silently let "80abc" through Number() later).
  const port = e['listen_port'];
  if (typeof port !== 'number' || !Number.isFinite(port) || port < 1 || port > 65535)
    return 'listen_port must be 1-65535';
  const targets = e['targets'];
  if (targets !== undefined) {
    if (!Array.isArray(targets) || targets.length === 0) return 'targets must not be empty';
    for (const target of targets) {
      if (!isImportEntry(target) || typeof target['host'] !== 'string' || target['host'].trim() === '') {
        return 'invalid target host';
      }
      if (typeof target['port'] !== 'number' || !Number.isInteger(target['port']) || target['port'] < 1 || target['port'] > 65535) {
        return 'invalid target port';
      }
      if (typeof target['enabled'] !== 'boolean') return 'invalid target enabled state';
    }
  }
  // `dest` is the legacy representation. New exports can have no enabled
  // destinations while still carrying valid disabled targets.
  const dest = e['dest'];
  if (!Array.isArray(dest) || (dest.length === 0 && (!Array.isArray(targets) || targets.length === 0))) {
    return 'dest must not be empty';
  }
  for (const d of dest) {
    if (typeof d !== 'string') return `invalid dest format: ${String(d)}`;
    if (!parseDest(d)) return `invalid dest format: ${d}`;
  }
  const protocol = e['protocol'];
  if (protocol !== undefined && (
    typeof protocol !== 'string' || !['tcp', 'udp', 'tcp_udp'].includes(protocol)
  )) return 'protocol must be tcp, udp, or tcp_udp';

  const publicTransport = e['public_transport'];
  if (publicTransport !== undefined && (
    typeof publicTransport !== 'string' || !['raw', 'nginx_sni'].includes(publicTransport)
  )) return 'public_transport must be raw or nginx_sni';

  const nodeTransport = e['node_transport'];
  if (nodeTransport !== undefined && (
    typeof nodeTransport !== 'string' || !['raw', 'nginx_sni'].includes(nodeTransport)
  )) return 'node_transport must be raw or nginx_sni';

  const sni = e['sni'];
  if (sni !== undefined && (typeof sni !== 'string' || sni.trim() === '')) return 'sni must be a non-empty string';
  const isSni = publicTransport === 'nginx_sni' || nodeTransport === 'nginx_sni' || typeof sni === 'string';
  if (isSni && (typeof sni !== 'string' || sni.trim() === '')) return 'sni is required for nginx_sni';

  const camouflageEnabled = e['camouflage_enabled'];
  if (camouflageEnabled !== undefined && typeof camouflageEnabled !== 'boolean') {
    return 'camouflage_enabled must be boolean';
  }

  const strategy = e['load_balance_strategy'];
  if (strategy !== undefined && (
    typeof strategy !== 'string' || !['first', 'round_robin', 'failover'].includes(strategy)
  )) return 'load_balance_strategy must be first, round_robin, or failover';
  return null;
}

/**
 * Coerce a validated entry to its typed form. ONLY safe to call after
 * `validateImportEntry(e) === null`; the caller MUST have validated first.
 * Centralises the `as` cast so the consuming code (handleImport) doesn't lie
 * about types in multiple places.
 */
export function asValidatedEntry(e: unknown): ValidatedImportEntry {
  // validateImportEntry already checked the runtime types; re-assert here only
  // to satisfy TS. This never throws for an entry that passed validation.
  const o = e as Record<string, unknown>;
  const sni = typeof o['sni'] === 'string' ? o['sni'].trim().toLowerCase() : undefined;
  const publicTransport =
    o['public_transport'] === 'nginx_sni' || o['node_transport'] === 'nginx_sni' || sni
      ? 'nginx_sni'
      : (o['public_transport'] as string | undefined);
  return {
    name: o['name'] as string,
    listen_port: o['listen_port'] as number,
    dest: o['dest'] as string[],
    targets: Array.isArray(o['targets'])
      ? (o['targets'] as RuleTargetInput[]).map(target => ({ ...target, host: target.host.trim() }))
      : undefined,
    protocol: o['protocol'] as string | undefined,
    public_transport: publicTransport,
    sni,
    camouflage_enabled: o['camouflage_enabled'] as boolean | undefined,
    load_balance_strategy: o['load_balance_strategy'] as string | undefined,
  };
}

/** Build the create payload for an imported rule. The caller supplies the
 * destination group; export files never carry source group IDs. */
export function buildImportedRulePayload(entry: ValidatedImportEntry, deviceGroupIn: number): ImportedRulePayload {
  const targets = entry.targets ?? entry.dest.map(d => {
    const target = parseDest(d);
    if (!target) throw new Error('validated import entry had an invalid dest');
    return { ...target, enabled: true };
  });
  const first = targets[0];
  const publicTransport = entry.public_transport === 'nginx_sni' ? 'nginx_sni' : 'raw';
  return {
    name: entry.name,
    listen_port: entry.listen_port,
    protocol: publicTransport === 'nginx_sni' ? 'tcp' : (entry.protocol ?? 'tcp_udp'),
    public_transport: publicTransport,
    forward_mode: 'direct',
    route_mode: 'direct',
    load_balance_strategy: entry.load_balance_strategy ?? 'first',
    upload_limit_mbps: 0,
    download_limit_mbps: 0,
    camouflage_enabled: entry.camouflage_enabled === true,
    sni: publicTransport === 'nginx_sni' ? entry.sni : undefined,
    device_group_in: deviceGroupIn,
    target_addr: first.host,
    target_port: first.port,
    targets,
  };
}
