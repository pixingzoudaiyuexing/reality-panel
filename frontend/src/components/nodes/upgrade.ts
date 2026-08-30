/**
 * Shared node-upgrade eligibility logic — used by BOTH the desktop table and
 * the mobile list so the two views can't drift. Pure function: given a node row
 * and the latest NODE release to compare against (PR5: nodes compare against
 * `latest_node_version`, NOT the panel version), plus a failed-check flag,
 * return the upgrade state.
 *
 * 核心不变量：配置协议不兼容不能阻断一键升级。只要 Node 比最新工件旧、
 * Lifecycle 通道在线且为 systemd 托管，就仍然返回 `upgradeable`；协议不兼容只
 * 阻断配置/普通控制能力。
 */
import type { NodeDisplayRow } from '../../api/types';
import { versionRelation } from '../../utils/version';

export type NodeUpgradeState =
  | 'none'
  | 'checkFailed'
  | 'protocolIncompatible'
  | 'unknown'
  | 'latest'
  | 'ahead'
  | 'docker'
  | 'manual'
  | 'upgradeable'
  | 'offline';

export interface NodeUpgrade {
  state: NodeUpgradeState;
}

/**
 * Resolve the upgrade affordance for one node row.
 *
 * `compareVersion` is the latest NODE release (NOT the panel version). When
 * `nodeVersionCheckFailed` is true the lookup failed and we MUST show a neutral
 * state (never a green check or an upgrade button based on a stale/empty value).
 *
 * Config protocol skew is deliberately NOT an early return when the node is
 * behind. That skew is exactly when the operator most needs the upgrade path.
 */
export function resolveNodeUpgrade(
  row: NodeDisplayRow,
  compareVersion: string,
  panelProtocol: number,
  nodeVersionCheckFailed: boolean,
): NodeUpgrade {
  if (!row.node_id) return { state: 'none' };
  if (nodeVersionCheckFailed) return { state: 'checkFailed' };

  const pv = row.config_protocol_version;
  const protocolMismatch = pv != null && panelProtocol > 0 && pv !== panelProtocol;
  const rel = versionRelation(row.node_version, compareVersion);

  if (rel === 'behind') {
    if (row.install_method === 'docker') return { state: 'docker' };
    if (row.install_method !== 'systemd') return { state: 'manual' };
    // Older payloads have no lifecycle_online field; preserve their established
    // online fallback while current Panels publish the authoritative WS state.
    const lifecycleOnline = row.lifecycle_online ?? row.online;
    return { state: lifecycleOnline ? 'upgradeable' : 'offline' };
  }

  // 没有更高版本可升时，协议不兼容仍应明确提示，而不是错误显示“已最新”。
  if (protocolMismatch) return { state: 'protocolIncompatible' };
  if (rel === 'unknown') return { state: 'unknown' };
  if (rel === 'ahead') return { state: 'ahead' };
  if (rel === 'same') return { state: 'latest' };
  return { state: 'unknown' };
}
