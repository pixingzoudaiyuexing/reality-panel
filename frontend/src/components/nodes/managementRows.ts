import type { NodeDisplayRow, PoolNode, SharedNodeSummary } from '../../api/types';
import { poolNodeKey, poolNodeName } from './poolNodeName';
import { compareNodeRows } from './sort';

export const statusNodeKey = (row: NodeDisplayRow) => `${row.group_id}:${row.node_id || ''}`;

/** Pool records survive missing status reports. Status-only/monitor/legacy rows
 * remain visible. Never infer identity from a public IP or a bare node ID. */
export function managementRows(rows: NodeDisplayRow[], pools: PoolNode[]): NodeDisplayRow[] {
  const byIdentity = new Map(rows.filter(row => row.node_id).map(row => [statusNodeKey(row), row]));
  for (const pool of pools) {
    const key = poolNodeKey(pool);
    const report = byIdentity.get(key);
    const unreported: SharedNodeSummary = {
      group_id: pool.identity_group_id, node_id: pool.node_id, group_name: '',
      connect_host: '', capabilities: '', connections: 0, online: pool.online,
    };
    byIdentity.set(key, { ...(report ?? unreported), group_name: poolNodeName(pool), online: pool.online,
      public_ipv4: pool.public_ipv4, public_ipv6: pool.public_ipv6,
      node_version: pool.node_version, last_seen: pool.last_seen ?? undefined });
  }
  return [...byIdentity.values(), ...rows.filter(row => !row.node_id)].sort(compareNodeRows);
}
