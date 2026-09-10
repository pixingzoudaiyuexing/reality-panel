import { Button, Dropdown, Modal, Space, Tag, Tooltip, Typography } from 'antd';
import type { MenuProps } from 'antd';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  CloudDownloadOutlined,
  DeleteOutlined,
  FileTextOutlined,
  InfoCircleOutlined,
  MoreOutlined,
  ReloadOutlined,
  StopOutlined,
} from '@ant-design/icons';
import type { NodeDisplayRow, RelayReadyNode } from '../../api/types';
import { formatBps, formatBytes, formatPercent, formatUptime } from '../../utils/format';
import { versionRelation, versionTagColor } from '../../utils/version';
import { NodeDiskBar, NodeResourceBar } from './NodeResourceBar';
import { RelayReadyStatus, statusTag } from './shared';
import type { NodeLifecycleHandler, Tfn } from './types';
import { resolveNodeUpgrade } from './upgrade';

const { Text } = Typography;

export function NodeStatusCell({
  row,
  panelProtocol,
  relayNode,
  showRelayReady,
  t,
}: {
  row: NodeDisplayRow;
  panelProtocol: number;
  relayNode?: RelayReadyNode;
  showRelayReady: boolean;
  t: Tfn;
}) {
  const protocolMismatch = row.config_protocol_version != null
    && panelProtocol > 0
    && row.config_protocol_version !== panelProtocol;
  return (
    <Space orientation="vertical" size={2} className="rp-node-status-cell" data-testid="node-status-cell">
      {statusTag(row, t, panelProtocol)}
      {protocolMismatch ? <Tag color={row.online ? 'green' : undefined}>{row.online ? t('online') : t('offline')}</Tag> : null}
      {showRelayReady ? <RelayReadyStatus node={relayNode} t={t} /> : null}
    </Space>
  );
}

export function NodeConnectionsCell({ row }: { row: NodeDisplayRow }) {
  return (
    <div className="rp-node-connections" data-testid="node-connections-cell">
      <div><Text type="secondary">TCP</Text><span className="rp-mono">{row.tcp_connections ?? '-'}</span></div>
      <div><Text type="secondary">UDP</Text><span className="rp-mono">{row.udp_sessions ?? '-'}</span></div>
    </div>
  );
}

function ResourceMetric({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rp-node-resource-metric">
      <Text type="secondary">{label}</Text>
      {children}
    </div>
  );
}

export function NodeResourcesCell({ row, t }: { row: NodeDisplayRow; t: Tfn }) {
  return (
    <div className="rp-node-resources" data-testid="node-resources-cell">
      <ResourceMetric label="CPU">
        <NodeResourceBar value={row.cpu} tooltip={`CPU: ${formatPercent(row.cpu)}`} />
      </ResourceMetric>
      <ResourceMetric label={t('mem')}>
        <NodeResourceBar value={row.mem} tooltip={`${t('mem')}: ${formatPercent(row.mem)}`} />
      </ResourceMetric>
      <ResourceMetric label={t('disk')}>
        <NodeDiskBar
          usagePercent={row.disk_usage_percent}
          used={row.disk_used}
          total={row.disk_total}
          mount={row.disk_mount}
          t={t}
        />
      </ResourceMetric>
    </div>
  );
}

export function NodeTrafficCell({ row }: { row: NodeDisplayRow }) {
  return (
    <div className="rp-node-traffic" data-testid="node-traffic-cell">
      <div className="rp-node-traffic-row">
        <ArrowUpOutlined aria-hidden="true" /> <span className="rp-mono">{formatBps(row.upload_bps)}</span>
        <ArrowDownOutlined aria-hidden="true" /> <span className="rp-mono">{formatBps(row.download_bps)}</span>
      </div>
      <div className="rp-node-traffic-row rp-node-traffic-total">
        <ArrowUpOutlined aria-hidden="true" /> <span className="rp-mono">{formatBytes(row.boot_upload_bytes)}</span>
        <ArrowDownOutlined aria-hidden="true" /> <span className="rp-mono">{formatBytes(row.boot_download_bytes)}</span>
      </div>
    </div>
  );
}

export function NodeUptimeCell({ row, t }: { row: NodeDisplayRow; t: Tfn }) {
  return (
    <span className="rp-mono" data-testid="node-uptime-cell">
      {formatUptime(row.uptime, { d: t('uptimeDay'), h: t('uptimeHour'), m: t('uptimeMinute'), s: t('uptimeSecond') })}
    </span>
  );
}

export function NodeMetadataCell({
  row,
  latestNodeVersion,
  nodeVersionCheckFailed,
}: {
  row: NodeDisplayRow;
  latestNodeVersion: string;
  nodeVersionCheckFailed: boolean;
}) {
  const versionColor = !row.node_version || nodeVersionCheckFailed
    ? undefined
    : versionTagColor(versionRelation(row.node_version, latestNodeVersion));
  return (
    <Space orientation="vertical" size={2} className="rp-node-metadata" data-testid="node-metadata-cell">
      {row.node_version ? <Tag color={versionColor} className="rp-mono">v{row.node_version}</Tag> : <Text type="secondary">-</Text>}
      <Text className="rp-mono" type={row.architecture ? undefined : 'secondary'}>{row.architecture || '-'}</Text>
    </Space>
  );
}

function iconButton(
  label: string,
  icon: React.ReactNode,
  onClick: () => void,
  disabled = false,
  danger = false,
  ariaLabel = label,
) {
  return (
    <Tooltip title={label}>
      <Button
        size="small"
        type="text"
        icon={icon}
        aria-label={ariaLabel}
        disabled={disabled}
        danger={danger}
        onClick={onClick}
      />
    </Tooltip>
  );
}

export function NodeActionControls({
  row,
  panelProtocol,
  latestNodeVersion,
  nodeVersionCheckFailed,
  artifactVersions,
  t,
  openDetail,
  onLifecycle,
  onUpgrade,
  onDelete,
}: {
  row: NodeDisplayRow;
  panelProtocol: number;
  latestNodeVersion: string;
  nodeVersionCheckFailed: boolean;
  artifactVersions: Record<string, string>;
  t: Tfn;
  openDetail: (row: NodeDisplayRow) => void;
  onLifecycle?: NodeLifecycleHandler;
  onUpgrade?: (row: NodeDisplayRow) => void;
  onDelete?: (row: NodeDisplayRow) => void;
}) {
  const arch = row.architecture === 'x86_64' ? 'amd64' : row.architecture === 'aarch64' ? 'arm64' : (row.architecture || '');
  const target = artifactVersions[arch];
  const protocolCompatible = row.config_protocol_version == null || panelProtocol <= 0 || row.config_protocol_version === panelProtocol;
  const normalLifecycleReady = !!row.node_id && !!row.online && row.install_method === 'systemd' && protocolCompatible;
  const lifecycleOnline = row.lifecycle_online ?? row.online;
  const canLifecycleUpgrade = !!row.node_id && !!lifecycleOnline && row.install_method === 'systemd' && !!target && target !== row.node_version;
  const standaloneUpgrade = onUpgrade ? resolveNodeUpgrade(row, latestNodeVersion, panelProtocol, nodeVersionCheckFailed) : null;

  const moreItems: MenuProps['items'] = [];
  if (onLifecycle) {
    moreItems.push({ key: 'uninstall', danger: true, icon: <StopOutlined />, label: t('nodeUninstall'), disabled: !normalLifecycleReady });
  }
  if (onDelete && !row.online) {
    moreItems.push({ key: 'delete', danger: true, icon: <DeleteOutlined />, label: t('removeNodeTitle') });
  }

  const onMoreClick: MenuProps['onClick'] = ({ key }) => {
    if (key === 'uninstall' && onLifecycle) onLifecycle(row, 'uninstall');
    if (key === 'delete' && onDelete) {
      Modal.confirm({
        title: t('removeNodeTitle'),
        content: t('removeNodeHint'),
        okText: t('confirmRemoveNode'),
        cancelText: t('cancel'),
        okButtonProps: { danger: true },
        onOk: () => onDelete(row),
      });
    }
  };

  return (
    <Space size={2} className="rp-node-actions" wrap data-testid="node-action-controls">
      {onLifecycle ? iconButton(t('nodeLogs'), <FileTextOutlined />, () => onLifecycle(row, 'logs'), !normalLifecycleReady) : null}
      {onLifecycle ? iconButton(t('nodeRestart'), <ReloadOutlined />, () => onLifecycle(row, 'restart'), !normalLifecycleReady) : null}
      {onLifecycle ? iconButton(
        target ? t('nodeUpgradeTip').replace('{v}', target) : t('nodeArtifactMissing'),
        <CloudDownloadOutlined />,
        () => onLifecycle(row, 'upgrade'),
        !canLifecycleUpgrade,
        false,
        t('nodeUpgrade'),
      ) : null}
      {!onLifecycle && onUpgrade && standaloneUpgrade?.state === 'upgradeable' ? iconButton(
        t('nodeUpgradeTip').replace('{v}', latestNodeVersion),
        <CloudDownloadOutlined />,
        () => onUpgrade(row),
      ) : null}
      {iconButton(t('nodeDetailsTitle'), <InfoCircleOutlined />, () => openDetail(row), !row.node_id)}
      {moreItems.length > 0 ? (
        <Dropdown menu={{ items: moreItems, onClick: onMoreClick }} trigger={['click']}>
          <Tooltip title={t('actions')}>
            <Button size="small" type="text" icon={<MoreOutlined />} aria-label={t('actions')} />
          </Tooltip>
        </Dropdown>
      ) : null}
    </Space>
  );
}
