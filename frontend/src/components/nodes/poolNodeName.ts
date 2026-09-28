import type { PoolNode } from '../../api/types';

export function poolNodeName(node: { display_name?: string | null; public_ipv4?: string | null; public_ipv6?: string | null; node_id: string }): string {
  return node.display_name?.trim() || node.public_ipv4 || node.public_ipv6 || node.node_id.slice(0, 12);
}

export function poolNodeKey(node: Pick<PoolNode, 'identity_group_id' | 'node_id'>): string {
  return `${node.identity_group_id}:${node.node_id}`;
}
