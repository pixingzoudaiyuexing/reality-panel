 
import { Tag, Typography, Collapse } from 'antd';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';
import type { NodeDisplayRow, RelayPreferenceView, RelayReadyNode } from '../../api/types';
import { useState } from 'react';
import type { NodeLifecycleHandler, Tfn } from './types';
import { NodeDesktopTable } from './NodeDesktopTable';
import { NodeMobileList } from './NodeMobileList';
import { RelayPreferencePanel } from './RelayPreferencePanel';
import { formatBps } from '../../utils/format';

const { Text } = Typography;

interface Props {
  rows: NodeDisplayRow[];
  panelProtocol: number;
  /** v1.2: the latest NODE release (bare, e.g. "1.1.0"). Nodes compare their
   *  own version against this — NOT the panel version. */
  latestNodeVersion: string;
  /** v1.2: the node-version lookup failed; tables show an unknown state. */
  nodeVersionCheckFailed: boolean;
  isMobile: boolean;
  t: Tfn;
  openDetail: (row: NodeDisplayRow) => void;
  /** v1.0.10: admin-only per-node upgrade trigger (desktop table only). */
  onUpgrade?: (row: NodeDisplayRow) => void;
  onLifecycle?: NodeLifecycleHandler;
  artifactVersions?: Record<string, string>;
  onDelete?: (row: NodeDisplayRow) => void;
  showRelayPreference?: boolean;
  onDiagnoseNode?: (groupId: number, node: RelayReadyNode) => void;
}

/** Per-group summary: online/total (placeholders excluded) + aggregate live
 *  upload/download across ONLINE nodes only. */
function groupSummary(rows: NodeDisplayRow[]) {
  const real = rows.filter((r) => r.node_id);
  const onlineRows = real.filter((r) => r.online);
  return {
    total: real.length,
    online: onlineRows.length,
    up: onlineRows.reduce((s, r) => s + (r.upload_bps || 0), 0),
    down: onlineRows.reduce((s, r) => s + (r.download_bps || 0), 0),
  };
}

/** One group block: header bar (name · ID · online/total · aggregate ↑↓) +
 *  either a desktop table or mobile list. Collapsible. A group with only a
 *  placeholder row shows "no node reporting". */
export function NodeGroupSection({ rows, panelProtocol, latestNodeVersion, nodeVersionCheckFailed, isMobile, t, openDetail, onUpgrade, onLifecycle, artifactVersions, onDelete, showRelayPreference = false, onDiagnoseNode }: Props) {
  const [relayPreference, setRelayPreference] = useState<RelayPreferenceView | null>(null);
  const head = rows[0];
  const { total, online, up, down } = groupSummary(rows);
  const region = head.region;
  const lineType = head.line_type;
  const onlyPlaceholder = rows.length === 1 && !head.node_id;
  const readyCount = relayPreference?.nodes.filter((node) => node.ready).length;
  const anomalyCount = relayPreference
    ? relayPreference.nodes.filter((node) => !node.online || !node.ready).length
    : null;

  const header = (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
      <Text strong>{head.group_name || '-'}</Text>
      <Text type="secondary" style={{ fontSize: 12 }}>ID: {head.group_id}</Text>
      {region ? <Tag>{region}</Tag> : null}
      {lineType ? <Tag color="blue">{lineType}</Tag> : null}
      <Text type="secondary" className="rp-group-node-summary">
        {t('nodes')} {total} · {t('online')} {online}
        {showRelayPreference ? ` · ${t('relayReady')} ${readyCount ?? '-'}` : ''}
        {showRelayPreference && anomalyCount !== null
          ? ` · ${t('nodeSummaryIssues').replace('{count}', String(anomalyCount))}`
          : ''}
      </Text>
      <span style={{ marginLeft: 'auto' }} className="rp-mono">
        <Text type="secondary" style={{ fontSize: 12 }}>
          <ArrowUpOutlined /> {formatBps(up)} <ArrowDownOutlined /> {formatBps(down)}
        </Text>
      </span>
    </div>
  );

  const nodeBody = onlyPlaceholder ? (
    <div style={{ padding: 12 }}>
      <Text type="secondary">{t('noNodeReportingInGroup')}</Text>
    </div>
  ) : isMobile ? (
    <div style={{ padding: 8 }}>
      <NodeMobileList
        rows={rows}
        panelProtocol={panelProtocol}
        latestNodeVersion={latestNodeVersion}
        nodeVersionCheckFailed={nodeVersionCheckFailed}
        t={t}
        openDetail={openDetail}
        onUpgrade={onUpgrade}
        onLifecycle={onLifecycle}
        artifactVersions={artifactVersions}
        relayNodes={relayPreference?.nodes}
        showRelayReady={showRelayPreference}
      />
    </div>
  ) : (
    <NodeDesktopTable rows={rows} panelProtocol={panelProtocol} latestNodeVersion={latestNodeVersion} nodeVersionCheckFailed={nodeVersionCheckFailed} t={t} openDetail={openDetail} onUpgrade={onUpgrade} onLifecycle={onLifecycle} artifactVersions={artifactVersions} onDelete={onDelete} relayNodes={relayPreference?.nodes} showRelayReady={showRelayPreference} />
  );

  const body = (
    <>
      {nodeBody}
      {showRelayPreference ? <RelayPreferencePanel groupId={head.group_id} t={t} onViewChange={setRelayPreference} onDiagnoseNode={onDiagnoseNode ? (node) => onDiagnoseNode(head.group_id, node) : undefined} /> : null}
    </>
  );

  return (
    <Collapse
      defaultActiveKey={['1']}
      style={{ marginBottom: 16 }}
      items={[{ key: '1', label: header, children: body }]}
    />
  );
}
