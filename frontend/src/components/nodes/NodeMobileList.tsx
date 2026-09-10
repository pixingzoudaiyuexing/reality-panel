
import { Space } from 'antd';
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
  latestNodeVersion?: string;
  /** v1.2: the node-version lookup failed; show a neutral state. */
  nodeVersionCheckFailed?: boolean;
  t: Tfn;
  openDetail: (row: NodeDisplayRow) => void;
  /** v1.0.10/v1.2: admin-only per-node upgrade trigger. When set, each card
   *  shows the node version + an upgrade affordance mirroring the desktop
   *  ladder (PR4), compared against the latest NODE release (PR5). */
  onUpgrade?: (row: NodeDisplayRow) => void;
  onLifecycle?: NodeLifecycleHandler;
  artifactVersions?: Record<string, string>;
  onDelete?: (row: NodeDisplayRow) => void;
  relayNodes?: RelayReadyNode[];
  showRelayReady?: boolean;
}

/** Mobile node cards reuse the same data presentation and actions as the
 * desktop table, but reorder them for status-first scanning without a table. */
export function NodeMobileList({ rows, panelProtocol, latestNodeVersion = '', nodeVersionCheckFailed = false, t, openDetail, onUpgrade, onLifecycle, artifactVersions = {}, onDelete, relayNodes = [], showRelayReady = false }: Props) {
  const relayById = new Map(relayNodes.map((node) => [node.node_id, node]));

  return (
    <Space orientation="vertical" style={{ width: '100%' }} size={8}>
      {rows.map((r) => {
        return (
          <div
            key={`${r.group_id}:${r.node_id || 'none'}`}
            // v1.2.5: offline cards are greyed, same signal as the desktop
            // table's offline rows — every figure on the card is the node's
            // last report rather than a live reading.
            className={`rp-node-mobile-card ${r.online ? '' : 'rp-node-offline-card'}`}
            data-testid="node-mobile-card"
          >
            <div className="rp-node-mobile-topline">
              <NodeStatusCell
                row={r}
                panelProtocol={panelProtocol}
                relayNode={r.node_id ? relayById.get(r.node_id) : undefined}
                showRelayReady={showRelayReady}
                t={t}
              />
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
            </div>
            <NetworkCell row={r} t={t} />
            <div className="rp-node-mobile-connections"><NodeConnectionsCell row={r} /></div>
            <NodeResourcesCell row={r} t={t} />
            <NodeTrafficCell row={r} />
            <div className="rp-node-mobile-footer">
              <NodeUptimeCell row={r} t={t} />
              <NodeMetadataCell row={r} latestNodeVersion={latestNodeVersion} nodeVersionCheckFailed={nodeVersionCheckFailed} />
            </div>
          </div>
        );
      })}
    </Space>
  );
}
