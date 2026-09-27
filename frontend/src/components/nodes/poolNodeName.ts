import type { PoolNode } from '../../api/types';

export function poolNodeName(node: Pick<PoolNode, 'display_name' | 'public_ipv4' | 'public_ipv6' | 'node_id'>): string {
  return node.display_name.trim() || node.public_ipv4 || node.public_ipv6 || node.node_id.slice(0, 12);
}

export function poolNodeKey(node: Pick<PoolNode, 'identity_group_id' | 'node_id'>): string {
  return `${node.identity_group_id}:${node.node_id}`;
}
