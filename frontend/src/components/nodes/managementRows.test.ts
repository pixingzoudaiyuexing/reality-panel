import { describe, expect, it } from 'vitest';
import type { NodeDisplayRow, PoolNode } from '../../api/types';
import { managementRows, statusNodeKey } from './managementRows';
const pool = (group: number, id: string): PoolNode => ({ identity_group_id: group, node_id: id, display_name: '',
  pool_native: true, public_ipv4: '203.0.113.1', public_ipv6: null, online: false, node_version: '1.4.8', last_seen: null,
  credential_ready: true, credential_active: true, safe_to_add: true, migration_incomplete: false, recovery_available: false,
  runtime_verified: true, migration_required: false, auth_reload_supported: true, memberships: [] });
const row = (group: number, id: string | null): NodeDisplayRow => ({ group_id: group, node_id: id, online: true,
  cpu: 42, mem: 30, connections: 12, uptime: 100, last_seen: 'last', public_ipv4: '203.0.113.1' });
describe('all-node identity and status projection', () => {
  it('keeps an anonymous legacy status distinct from a concrete node named legacy', () => {
    expect(statusNodeKey(row(1, null))).not.toBe(statusNodeKey(row(1, 'legacy')));
  });
  it('joins by composite identity and retains each same-ID or same-IP identity', () => {
    const rows = managementRows([row(1, 'same'), row(2, 'same'), row(3, 'other')], [pool(1, 'same')]);
    expect(rows).toHaveLength(3);
    expect(rows.find(r => r.group_id === 1)?.cpu).toBe(42);
    expect(rows.find(r => r.group_id === 1)?.online).toBe(false);
    expect(rows.find(r => r.group_id === 2)?.online).toBe(true);
  });
  it('keeps unreported and unassigned pool nodes without inventing metrics', () => {
    const rows = managementRows([], [pool(9, 'unreported')]);
    expect(rows).toHaveLength(1);
    expect(rows[0].group_id).toBe(9);
    expect(rows[0].node_id).toBe('unreported');
    expect(rows[0].cpu).toBeUndefined();
    expect(rows[0].tcp_connections).toBeUndefined();
  });
  it('preserves monitor/status-only and null-ID legacy rows', () => {
    const rows = managementRows([row(1, 'monitor'), row(2, null)], []);
    expect(rows).toHaveLength(2);
    expect(rows.some(r => r.node_id === null)).toBe(true);
  });
  it('does not alter API reports when overlaying Pool metadata', () => {
    const report = row(1, 'node');
    managementRows([report], [pool(1, 'node')]);
    expect(report.online).toBe(true);
    expect(report.node_version).toBeUndefined();
  });
});
