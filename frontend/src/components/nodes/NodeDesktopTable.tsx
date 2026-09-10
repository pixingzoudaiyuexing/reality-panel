import { Table, Tooltip } from 'antd';
import type { NodeLifecycleHandler, Tfn } from './types';
import type { NodeDisplayRow, RelayReadyNode } from '../../api/types';
import { NetworkCell } from './shared';
import {
  NodeActionControls,
  NodeConnectionsCell,
  NodeMetadataCell,
  NodeResourcesCell,
  NodeStatusCell,
  NodeTrafficCell,
  NodeUptimeCell,
} from './NodeStatusCells';

interface Props {
  rows: NodeDisplayRow[];
  panelProtocol: number;
  /** v1.2: the latest NODE release (bare, e.g. "1.1.0"). Nodes compare their
   *  own version against this — NOT the panel version. Empty when unknown. */
  latestNodeVersion: string;
  /** v1.2: the node-version lookup failed; show an unknown state. */
  nodeVersionCheckFailed: boolean;
  t: Tfn;
  openDetail: (row: NodeDisplayRow) => void;
  /** v1.0.10: admin-only. When set, a "节点更新" column shows a per-node upgrade
   *  icon (active when the node is behind the latest node release). Absent for
   *  the regular-user view. */
  onUpgrade?: (row: NodeDisplayRow) => void;
  onLifecycle?: NodeLifecycleHandler;
  artifactVersions?: Record<string, string>;
  /** v1.2.5: admin-only. Removes this node's status record. Offered ONLY for
   *  offline rows — deleting an online node's record achieves nothing, because
   *  the next report (within ~10s) recreates it. Absent for the user view. */
  onDelete?: (row: NodeDisplayRow) => void;
  relayNodes?: RelayReadyNode[];
  showRelayReady?: boolean;
}

/** Desktop table for one group's nodes. Both admin and user share the same
 *  columns — the permission difference is in the data source (admin reads
 *  /nodes, user reads /nodes/shared) and the detail drawer. */
export function NodeDesktopTable({ rows, panelProtocol, latestNodeVersion, nodeVersionCheckFailed, t, openDetail, onUpgrade, onLifecycle, artifactVersions = {}, onDelete, relayNodes = [], showRelayReady = false }: Props) {
  const relayById = new Map(relayNodes.map((node) => [node.node_id, node]));

  const columns = [
    {
      title: t('status'), key: 'status', width: 116, fixed: 'left' as const,
      render: (_: unknown, r: NodeDisplayRow) => (
        <NodeStatusCell
          row={r}
          panelProtocol={panelProtocol}
          relayNode={r.node_id ? relayById.get(r.node_id) : undefined}
          showRelayReady={showRelayReady}
          t={t}
        />
      ),
    },
    {
      title: t('network'), key: 'network', width: 228,
      render: (_: unknown, r: NodeDisplayRow) => <NetworkCell row={r} t={t} compact />,
    },
    {
      title: <Tooltip title={`${t('tcpActiveConnections')} / ${t('udpActiveSessions')}`}>TCP / UDP</Tooltip>,
      key: 'connections', width: 82,
      render: (_: unknown, r: NodeDisplayRow) => <NodeConnectionsCell row={r} />,
    },
    {
      title: t('nodeResources'), key: 'resources', width: 180,
      render: (_: unknown, r: NodeDisplayRow) => <NodeResourcesCell row={r} t={t} />,
    },
    {
      title: t('traffic'), key: 'traffic', width: 184,
      render: (_: unknown, r: NodeDisplayRow) => <NodeTrafficCell row={r} />,
    },
    {
      title: t('systemUptime'), key: 'uptime', width: 90,
      render: (_: unknown, r: NodeDisplayRow) => <NodeUptimeCell row={r} t={t} />,
    },
    {
      title: t('nodeInformation'), key: 'metadata', width: 120,
      render: (_: unknown, r: NodeDisplayRow) => (
        <NodeMetadataCell row={r} latestNodeVersion={latestNodeVersion} nodeVersionCheckFailed={nodeVersionCheckFailed} />
      ),
    },
    {
      title: t('nodeOperations'), key: 'actions', width: 166, fixed: 'right' as const,
      render: (_: unknown, r: NodeDisplayRow) => (
        <NodeActionControls
          row={r}
          panelProtocol={panelProtocol}
          latestNodeVersion={latestNodeVersion}
          nodeVersionCheckFailed={nodeVersionCheckFailed}
          artifactVersions={artifactVersions}
          t={t}
          openDetail={openDetail}
          onLifecycle={onLifecycle}
          onUpgrade={onUpgrade}
          onDelete={onDelete}
        />
      ),
    },
  ];

  return (
    <Table
      dataSource={rows}
      columns={columns}
      rowKey={(r) => `${r.group_id}:${r.node_id || 'legacy'}`}
      // v1.2.5: offline rows are greyed (see .rp-node-offline in theme.css).
      // Their numbers are the last report, not a live reading — and since these
      // rows now stay listed for 24h instead of 2 minutes, telling them apart
      // at a glance is what makes the longer retention useful rather than noisy.
      rowClassName={(r) => (r.online ? '' : 'rp-node-offline')}
      pagination={false}
      size="small"
      scroll={{ x: 1080 }}
    />
  );
}
