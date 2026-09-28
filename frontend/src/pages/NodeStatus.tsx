import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Spin, Result, Empty, Modal, message, Button, Drawer, Input, Tag, Typography, Badge, List, Space, Descriptions, Progress } from 'antd';
import { CloudUploadOutlined, CopyOutlined, LineChartOutlined, ReloadOutlined, UnorderedListOutlined, SyncOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import type { ApiEnvelope, DeviceGroup, SharedNodeSummary, NodeDisplayRow, NodeLifecycleAction, NodeOperation, NodeArtifactCatalog, RelayReadyNode, BatchUpgradeOperation, BatchUpgradePreview, BatchUpgradeItemStatus, NodeHealthSnapshot } from '../api/types';
import { useI18n } from '../i18n/context';
import { useAuth } from '../auth/useAuth';
import { NodeGroupSection } from '../components/nodes/NodeGroupSection';
import { NodeDetailDrawer } from '../components/nodes/NodeDetailDrawer';
import { stableGroupedRows } from '../components/nodes/sort';
import { NodeDiagnosisDrawer } from '../components/diagnosis/NodeDiagnosisDrawer';
import { operationStatusLabel } from '../components/nodes/lifecycleStatus';
import { poolNodeName } from '../components/nodes/poolNodeName';

type AnyNodeRow = NodeDisplayRow;

const terminalOperationStatuses = new Set(['SUCCESS', 'FAILED', 'TIMEOUT']);
const terminalBatchStatuses = new Set(['SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'INTERRUPTED']);
const EXPANDED_GROUP_STORAGE_KEY = 'reality-panel:node-status:expanded-group';

function readExpandedGroupId(): number | null {
  try {
    const raw = window.localStorage.getItem(EXPANDED_GROUP_STORAGE_KEY);
    if (raw === null) return null;
    const value = Number(raw);
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

function persistExpandedGroupId(groupId: number | null) {
  try {
    if (groupId === null) window.localStorage.removeItem(EXPANDED_GROUP_STORAGE_KEY);
    else window.localStorage.setItem(EXPANDED_GROUP_STORAGE_KEY, String(groupId));
  } catch {
    // Storage can be unavailable in private/restricted browser contexts.
  }
}

/** Hook: is the viewport mobile-width? Re-evaluates on resize. */
function useIsMobile(breakpoint = 768): boolean {
  const [mobile, setMobile] = useState(() => window.innerWidth < breakpoint);
  useEffect(() => {
    const onResize = () => setMobile(window.innerWidth < breakpoint);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [breakpoint]);
  return mobile;
}

/**
 * v0.4.15 PR3: unified full-width node status board. Both admins and regular
 * users land here after login (via the sidebar). Admin reads /admin/node-health; regular
 * users read /nodes/shared (server-side field filtering — the frontend never
 * hides sensitive fields client-side).
 */
export default function NodeStatus() {
  const { t } = useI18n();
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const isMobile = useIsMobile();

  const [health, setHealth] = useState<NodeHealthSnapshot[] | null>(null);
  const [userRows, setUserRows] = useState<SharedNodeSummary[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [artifactVersions, setArtifactVersions] = useState<Record<string, string>>({});
  const [panelProtocol, setPanelProtocol] = useState(0);
  const [inboundGroupIds, setInboundGroupIds] = useState<Set<number>>(() => new Set());
  const [detailRow, setDetailRow] = useState<AnyNodeRow | null>(null);
  const [activeOperation, setActiveOperation] = useState<NodeOperation | null>(null);
  const [operationDrawerOpen, setOperationDrawerOpen] = useState(false);
  const [backgroundTasks, setBackgroundTasks] = useState<NodeOperation[]>([]);
  const [backgroundTasksOpen, setBackgroundTasksOpen] = useState(false);
  const [batchOperations, setBatchOperations] = useState<BatchUpgradeOperation[]>([]);
  const [batchPreview, setBatchPreview] = useState<BatchUpgradePreview | null>(null);
  const [batchPreviewOpen, setBatchPreviewOpen] = useState(false);
  const [batchStarting, setBatchStarting] = useState(false);
  const [activeBatch, setActiveBatch] = useState<BatchUpgradeOperation | null>(null);
  const [batchDrawerOpen, setBatchDrawerOpen] = useState(false);
  const [uninstallRow, setUninstallRow] = useState<AnyNodeRow | null>(null);
  const [uninstallConfirmation, setUninstallConfirmation] = useState('');
  const [nodeDiagnosisTarget, setNodeDiagnosisTarget] = useState<{ groupId: number; nodeId: string; label: string } | null>(null);
  const [expandedGroupId, setExpandedGroupId] = useState<number | null>(readExpandedGroupId);
  // Guards against overlapping polls: on a slow network (axios 10s timeout vs
  // 5s interval) a new tick could otherwise fire before the previous request
  // returned, stacking requests.
  const inFlightRef = useRef(false);
  const hasLoadedRowsRef = useRef(false);

  const loadAdmin = async () => {
    try {
      const snapshot = await api.get<unknown, ApiEnvelope<NodeHealthSnapshot[]>>('/admin/node-health');
      if (snapshot.code !== 0 || !Array.isArray(snapshot.data)) throw new Error(snapshot.message);
      setLoadFailed(false);
      setHealth(snapshot.data);
      hasLoadedRowsRef.current = true;
    } catch {
      setHealth(null);
      setLoadFailed(true);
    }
  };

  const loadUser = async () => {
    try {
      const res = await api.get<unknown, ApiEnvelope<SharedNodeSummary[]>>('/nodes/shared');
      if (res.code !== 0) {
        if (!hasLoadedRowsRef.current) setLoadFailed(true);
        return;
      }
      setLoadFailed(false);
      setUserRows(res.data || []);
      hasLoadedRowsRef.current = true;
    } catch {
      if (!hasLoadedRowsRef.current) setLoadFailed(true);
    }
  };

  const loadLifecycleMetadata = async () => {
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeArtifactCatalog>>('/admin/node-artifacts');
      if (res.code !== 0 || !res.data) return;
      setPanelProtocol(res.data.config_protocol_version || 0);
      setArtifactVersions(Object.fromEntries(
        res.data.artifacts
          .filter((artifact) => artifact.available && artifact.version)
          .map((artifact) => [artifact.architecture, artifact.version as string]),
      ));
    } catch { /* ignore */ }
    try {
      const res = await api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups');
      setInboundGroupIds(new Set((res.data ?? []).filter((group) => group.group_type === 'in').map((group) => group.id)));
    } catch {
      setInboundGroupIds(new Set());
    }
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeOperation[]>>('/admin/node-operations');
      if (res.code === 0) setBackgroundTasks(res.data ?? []);
    } catch { /* discovery is best-effort */ }
    try {
      const res = await api.get<unknown, ApiEnvelope<BatchUpgradeOperation[]>>('/admin/nodes/batch-upgrades');
      if (res.code === 0) setBatchOperations(res.data ?? []);
    } catch { /* discovery is best-effort */ }
  };

  const refresh = async () => {
    // Skip this tick if the previous request is still outstanding.
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      await (isAdmin ? loadAdmin() : loadUser());
    } finally {
      inFlightRef.current = false;
    }
  };

  // Poll the unified health observation every 5s. Version metadata is static
  // for the lifetime of a panel process, so it's fetched once on mount (admin
  // only). An admin health failure clears the prior observation, so stale
  // readiness cannot be presented as current.
  useEffect(() => {
    hasLoadedRowsRef.current = false;
    if (isAdmin) loadLifecycleMetadata();
    refresh();
    const ti = setInterval(refresh, 5000);
    const onFocus = () => void refresh();
    const onVisibility = () => { if (document.visibilityState === 'visible') void refresh(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      clearInterval(ti);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  const errorMessage = useCallback((error: unknown) => {
    const payload = (error as { response?: { data?: { message?: string } } })?.response?.data;
    return payload?.message || t('nodeOperationFailed');
  }, [t]);

  const copyLogs = async () => {
    if (!activeOperation?.logs) return;
    try {
      await navigator.clipboard.writeText(activeOperation.logs);
      message.success(t('copied'));
    } catch {
      message.error(t('copyFailed'));
    }
  };

  useEffect(() => {
    if (!operationDrawerOpen || !activeOperation || terminalOperationStatuses.has(activeOperation.status)) return;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const res = await api.get<unknown, ApiEnvelope<NodeOperation>>(
          `/admin/nodes/${activeOperation.group_id}/${activeOperation.node_id}/operations/${activeOperation.id}`,
        );
        if (cancelled) return;
        if (res.code !== 0 || !res.data) throw new Error(res.message);
        setActiveOperation(res.data);
        setBackgroundTasks((current) => [res.data as NodeOperation, ...current.filter((item) => item.id !== res.data?.id)]);
        if (!terminalOperationStatuses.has(res.data.status)) timer = window.setTimeout(poll, 1000);
      } catch (error) {
        if (!cancelled) message.error(errorMessage(error));
      }
    };
    timer = window.setTimeout(poll, 1000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeOperation, errorMessage, operationDrawerOpen]);

  useEffect(() => {
    if (!batchDrawerOpen || !activeBatch || terminalBatchStatuses.has(activeBatch.status)) return;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const res = await api.get<unknown, ApiEnvelope<BatchUpgradeOperation>>(`/admin/nodes/batch-upgrade/${activeBatch.id}`);
        if (cancelled) return;
        if (res.code !== 0 || !res.data) throw new Error(res.message);
        setActiveBatch(res.data);
        setBatchOperations((current) => [res.data as BatchUpgradeOperation, ...current.filter((item) => item.id !== res.data?.id)]);
        if (!terminalBatchStatuses.has(res.data.status)) timer = window.setTimeout(poll, 1000);
      } catch (error) {
        if (!cancelled) message.error(errorMessage(error));
      }
    };
    timer = window.setTimeout(poll, 1000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeBatch, batchDrawerOpen, errorMessage]);

  const startOperation = async (row: AnyNodeRow, action: NodeLifecycleAction, confirmation?: string) => {
    if (!row.node_id) return;
    const identityGroupId = row.identity_group_id ?? row.group_id;
    try {
      const res = action === 'logs'
        ? await api.get<unknown, ApiEnvelope<NodeOperation>>(`/admin/nodes/${identityGroupId}/${row.node_id}/logs?lines=200`)
        : await api.post<unknown, ApiEnvelope<NodeOperation>>(
            `/admin/nodes/${identityGroupId}/${row.node_id}/operations/${action}`,
            confirmation ? { confirmation } : {},
          );
      if (res.code !== 0 || !res.data) { message.error(res.message); return; }
      setActiveOperation(res.data);
      setOperationDrawerOpen(true);
      setBackgroundTasks((current) => [res.data as NodeOperation, ...current.filter((item) => item.id !== res.data?.id)]);
    } catch (error) {
      message.error(errorMessage(error));
    }
  };

  const openOperationDetail = async (operation: NodeOperation) => {
    setActiveOperation(operation);
    setBackgroundTasksOpen(false);
    setOperationDrawerOpen(true);
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeOperation>>(
        `/admin/nodes/${operation.group_id}/${operation.node_id}/operations/${operation.id}`,
      );
      if (res.code === 0 && res.data) setActiveOperation(res.data);
    } catch { /* keep the discovered snapshot */ }
  };

  const handleLifecycle = (row: AnyNodeRow, action: NodeLifecycleAction) => {
    if (action === 'logs') { void startOperation(row, action); return; }
    if (action === 'uninstall') {
      setUninstallConfirmation('');
      setUninstallRow(row);
      return;
    }
    const target = action === 'upgrade'
      ? artifactVersions[row.architecture === 'x86_64' ? 'amd64' : row.architecture === 'aarch64' ? 'arm64' : (row.architecture || '')]
      : undefined;
    Modal.confirm({
      title: action === 'restart' ? t('nodeRestartConfirmTitle') : t('nodeUpgradeConfirmTitle'),
      content: action === 'restart'
        ? t('nodeRestartConfirm')
        : t('nodeUpgradeConfirm').replace('{v}', target || '-'),
      okText: action === 'restart' ? t('nodeRestart') : t('nodeUpgradeOk'),
      cancelText: t('cancel'),
      onOk: () => startOperation(row, action),
    });
  };

  const handleDiagnoseNode = (groupId: number, node: RelayReadyNode) => {
    const nodeId = node.node_id.trim();
    if (!nodeId) return;
    setNodeDiagnosisTarget({ groupId: node.identity_group_id ?? groupId, nodeId, label: poolNodeName(node) });
  };

  const openBatchUpgrade = async () => {
    const running = batchOperations.find((batch) => !terminalBatchStatuses.has(batch.status));
    if (running) {
      await openBatchDetail(running);
      return;
    }
    try {
      const res = await api.get<unknown, ApiEnvelope<BatchUpgradePreview>>('/admin/nodes/batch-upgrade/preview');
      if (res.code !== 0 || !res.data) throw new Error(res.message);
      setBatchPreview(res.data);
      setBatchPreviewOpen(true);
    } catch (error) {
      message.error(errorMessage(error));
    }
  };

  const openBatchDetail = async (batch: BatchUpgradeOperation) => {
    setActiveBatch(batch);
    setBackgroundTasksOpen(false);
    setBatchDrawerOpen(true);
    try {
      const res = await api.get<unknown, ApiEnvelope<BatchUpgradeOperation>>(`/admin/nodes/batch-upgrade/${batch.id}`);
      if (res.code === 0 && res.data) setActiveBatch(res.data);
    } catch { /* keep the discovered snapshot */ }
  };

  const startBatchUpgrade = async () => {
    setBatchStarting(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<BatchUpgradeOperation>>('/admin/nodes/batch-upgrade', {});
      if (res.code !== 0 || !res.data) throw new Error(res.message);
      setBatchPreviewOpen(false);
      setActiveBatch(res.data);
      setBatchOperations((current) => [res.data as BatchUpgradeOperation, ...current.filter((item) => item.id !== res.data?.id)]);
      setBatchDrawerOpen(true);
    } catch (error) {
      message.error(errorMessage(error));
    } finally {
      setBatchStarting(false);
    }
  };

  const rows: AnyNodeRow[] | null = isAdmin
    ? (() => {
      if (!health) return null;
      const projected: NodeDisplayRow[] = [];
      for (const snapshot of health) {
        const t = snapshot.telemetry;
        const base: NodeDisplayRow = {
          group_id: snapshot.identity_group_id,
          group_name: snapshot.identity_group_name ?? '节点池',
          identity_group_id: snapshot.identity_group_id,
          node_id: snapshot.node_id,
          legacy_status: snapshot.legacy_status,
          display_name: snapshot.display_name,
          health_state: snapshot.state,
          online: t.fresh,
          lifecycle_online: snapshot.control?.lifecycle_connected ?? snapshot.control_connected,
          verified_concrete_node: t.verified_concrete_node ?? undefined,
          auth_reload_supported: t.auth_reload_supported ?? undefined,
          cpu: t.cpu, mem: t.mem, uptime: t.uptime, process_uptime: t.process_uptime,
          disk_total: t.disk_total, disk_used: t.disk_used, disk_usage_percent: t.disk_usage_percent,
          disk_mount: t.disk_mount, upload_bps: t.upload_bps, download_bps: t.download_bps,
          boot_upload_bytes: t.boot_upload_bytes, boot_download_bytes: t.boot_download_bytes,
          network_interface: t.network_interface, connections: t.connections,
          tcp_connections: t.tcp_connections, udp_sessions: t.udp_sessions,
          public_ip: t.public_ip, public_ipv4: t.public_ipv4, public_ipv6: t.public_ipv6,
          ipv4_country_code: t.ipv4_country_code, ipv4_country_name: t.ipv4_country_name,
          ipv6_country_code: t.ipv6_country_code, ipv6_country_name: t.ipv6_country_name,
          node_version: t.node_version, architecture: t.architecture,
          install_method: t.install_method, config_protocol_version: t.config_protocol_version,
          last_seen: t.last_seen, listener_errors: snapshot.runtime.listener_errors,
          reconciliation: snapshot.runtime.reconciliation,
        };
        projected.push(base);
        for (const membership of snapshot.group_readiness) {
          if (membership.group_id === snapshot.identity_group_id) continue;
          projected.push({
            ...base,
            group_id: membership.group_id,
            group_name: membership.group_name,
          });
        }
      }
      return projected;
    })()
    : userRows;
  const currentDetail = detailRow && rows?.find((row) => row.group_id === detailRow.group_id
    && row.node_key === detailRow.node_key
    && (row.identity_group_id ?? row.group_id) === (detailRow.identity_group_id ?? detailRow.group_id)
    && row.node_id === detailRow.node_id) || null;
  const groups = useMemo(() => (rows ? stableGroupedRows(rows) : null), [rows]);

  useEffect(() => {
    if (!groups || expandedGroupId === null) return;
    if (!groups.some(([groupId]) => groupId === expandedGroupId)) {
      setExpandedGroupId(null);
      persistExpandedGroupId(null);
    }
  }, [expandedGroupId, groups]);

  const toggleExpandedGroup = (groupId: number, expanded: boolean) => {
    const next = expanded ? groupId : null;
    setExpandedGroupId(next);
    persistExpandedGroupId(next);
  };

  const title = t('nodeStatus');
  const activeTaskCount = backgroundTasks.filter((operation) => !terminalOperationStatuses.has(operation.status)).length
    + batchOperations.filter((batch) => !terminalBatchStatuses.has(batch.status)).length;
  const pageTitle = (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
      <h2 className="rp-page-title"><LineChartOutlined /> {title}</h2>
      {isAdmin && (
        <Space wrap>
          <Badge count={activeTaskCount} size="small">
            <Button icon={<UnorderedListOutlined />} onClick={() => setBackgroundTasksOpen(true)}>{t('backgroundTasks')}</Button>
          </Badge>
          <Button icon={<SyncOutlined />} onClick={() => void openBatchUpgrade()}>{t('batchUpgradeAll')}</Button>
          <Button type="primary" icon={<CloudUploadOutlined />} onClick={() => navigate('/node-bootstrap')}>{t('nodeBootstrapTitle')}</Button>
        </Space>
      )}
    </div>
  );

  // Load failure (DB error / request failure) — not a normal empty state.
  // v0.4.15 PR3: applies to admins too (loadAdmin now surfaces failures).
  if (loadFailed) {
    return (
      <>
        {pageTitle}
        <Result status="warning" title={t('loadFailed')} subTitle={t('loadFailedRetry')} />
      </>
    );
  }

  if (rows === null || groups === null) {
    return <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>;
  }

  // No groups at all.
  if (groups.length === 0) {
    return (
      <>
        {pageTitle}
        <Result
          status="info"
          icon={<Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
          title={isAdmin ? t('noNodesHint') : t('adminNoLines')}
        />
      </>
    );
  }

  // v1.2.5: drop one node's status record. Admin-only, and the button is only
  // rendered on offline rows — see NodeDesktopTable for why.
  const handleDelete = async (row: NodeDisplayRow) => {
    try {
      const qs = row.node_id ? `?node_id=${encodeURIComponent(row.node_id)}` : '';
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/nodes/${row.identity_group_id ?? row.group_id}${qs}`);
      if (res.code !== 0) { message.error(res.message || t('nodeRemoveFailed')); return; }
      message.success(t('nodeRemoved'));
      refresh();
    } catch {
      message.error(t('nodeRemoveFailed'));
    }
  };

  return (
    <>
      {pageTitle}
      {groups.map(([gid, groupRows]) => (
        <NodeGroupSection
          key={gid}
          rows={groupRows}
          panelProtocol={panelProtocol}
          latestNodeVersion=""
          nodeVersionCheckFailed={false}
          isMobile={isMobile}
          t={t}
          openDetail={setDetailRow}
          onLifecycle={isAdmin ? handleLifecycle : undefined}
          artifactVersions={artifactVersions}
          onDelete={isAdmin ? handleDelete : undefined}
          showRelayPreference={isAdmin && inboundGroupIds.has(gid)}
          healthNodes={health?.filter((node) => node.group_readiness.some((group) => group.group_id === gid)) ?? []}
          onDiagnoseNode={isAdmin ? handleDiagnoseNode : undefined}
          expanded={expandedGroupId === gid}
          onExpandedChange={(expanded) => toggleExpandedGroup(gid, expanded)}
        />
      ))}
      <NodeDetailDrawer
        row={currentDetail}
        open={currentDetail !== null}
        onClose={() => setDetailRow(null)}
        isAdmin={isAdmin}
        panelProtocol={panelProtocol}
        onDeleted={refresh}
      />
      <NodeDiagnosisDrawer target={nodeDiagnosisTarget} onClose={() => setNodeDiagnosisTarget(null)} t={t} />
      <Drawer
        title={activeOperation ? t(`nodeOperation_${activeOperation.action}`) : t('nodeOperations')}
        open={operationDrawerOpen}
        onClose={() => setOperationDrawerOpen(false)}
        size={isMobile ? '100%' : 640}
        extra={activeOperation ? (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            {activeOperation.action === 'logs' ? (
              <>
                <Button
                  size="small"
                  icon={<CopyOutlined />}
                  disabled={!activeOperation.logs}
                  onClick={() => void copyLogs()}
                >
                  {t('nodeCopyLogs')}
                </Button>
                <Button
                  size="small"
                  icon={<ReloadOutlined />}
                  onClick={() => startOperation({ group_id: activeOperation.group_id, node_id: activeOperation.node_id }, 'logs')}
                >
                  {t('refresh')}
                </Button>
              </>
            ) : null}
            <Tag color={activeOperation.status === 'SUCCESS' ? 'green' : activeOperation.status === 'FAILED' || activeOperation.status === 'TIMEOUT' ? 'red' : 'blue'}>{operationStatusLabel(activeOperation, t)}</Tag>
          </span>
        ) : null}
      >
        {activeOperation ? (
          <>
            <Typography.Paragraph>{activeOperation.message}</Typography.Paragraph>
            <Typography.Text type="secondary">
              {activeOperation.architecture || '-'} · {activeOperation.current_version ? `v${activeOperation.current_version}` : '-'}
              {activeOperation.target_version ? ` → v${activeOperation.target_version}` : ''}
            </Typography.Text>
            {activeOperation.logs !== undefined ? (
              <pre style={{ marginTop: 16, maxHeight: '70vh', overflow: 'auto', whiteSpace: 'pre-wrap', fontSize: 12 }}>{activeOperation.logs || t('nodeLogsEmpty')}</pre>
            ) : null}
          </>
        ) : null}
      </Drawer>
      <Drawer title={t('backgroundTasks')} open={backgroundTasksOpen} onClose={() => setBackgroundTasksOpen(false)} size={isMobile ? '100%' : 640}>
        <Typography.Title level={5}>{t('batchUpgrades')}</Typography.Title>
        <List
          dataSource={batchOperations}
          locale={{ emptyText: t('backgroundTasksEmpty') }}
          renderItem={(batch) => (
            <List.Item actions={[
              <Button key="view" type="link" onClick={() => void openBatchDetail(batch)}>{t('details')}</Button>,
            ]}>
              <List.Item.Meta
                title={`${t('batchUpgradeAll')} · ${t(`batchUpgradeStatus_${batch.status}`)}`}
                description={`${batch.success + batch.failed + batch.skipped} / ${batch.total} · ${batch.updated_at}`}
              />
            </List.Item>
          )}
        />
        <Typography.Title level={5} style={{ marginTop: 24 }}>{t('singleNodeOperations')}</Typography.Title>
        <List
          dataSource={backgroundTasks}
          locale={{ emptyText: t('backgroundTasksEmpty') }}
          renderItem={(operation) => (
            <List.Item actions={[
              <Button key="view" type="link" onClick={() => void openOperationDetail(operation)}>{t('details')}</Button>,
            ]}>
              <List.Item.Meta
                title={`${operation.node_id} · ${t(`nodeOperation_${operation.action}`)}`}
                description={`G${operation.group_id} · ${operationStatusLabel(operation, t)} · ${operation.current_version ? `v${operation.current_version}` : '-'}${operation.target_version ? ` → v${operation.target_version}` : ''} · ${operation.updated_at}`}
              />
            </List.Item>
          )}
        />
      </Drawer>
      <Modal
        title={t('batchUpgradeConfirmTitle')}
        open={batchPreviewOpen}
        okText={t('batchUpgradeStart')}
        cancelText={t('cancel')}
        confirmLoading={batchStarting}
        okButtonProps={{ disabled: !batchPreview || batchPreview.pending === 0 }}
        onCancel={() => setBatchPreviewOpen(false)}
        onOk={() => void startBatchUpgrade()}
      >
        {batchPreview ? (
          <>
            <Descriptions column={1} size="small">
              <Descriptions.Item label={t('batchUpgradeTarget')}>v{batchPreview.target_version ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('batchUpgradeEligible')}>{batchPreview.pending}</Descriptions.Item>
              <Descriptions.Item label={t('batchUpgradeAlreadyCurrent')}>{batchPreview.already_current}</Descriptions.Item>
              <Descriptions.Item label={t('batchUpgradeOffline')}>{batchPreview.offline}</Descriptions.Item>
              <Descriptions.Item label={t('batchUpgradeOtherSkipped')}>{Math.max(0, batchPreview.skipped - batchPreview.already_current - batchPreview.offline)}</Descriptions.Item>
            </Descriptions>
            <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>{t('batchUpgradeRollingHint')}</Typography.Paragraph>
            <Typography.Paragraph type="secondary">{t('batchUpgradeBackgroundHint')}</Typography.Paragraph>
          </>
        ) : null}
      </Modal>
      <Drawer
        title={t('batchUpgradeProgressTitle')}
        open={batchDrawerOpen}
        onClose={() => setBatchDrawerOpen(false)}
        size={isMobile ? '100%' : 680}
        extra={activeBatch ? <Tag color={activeBatch.status === 'SUCCESS' ? 'green' : activeBatch.status === 'PARTIAL_SUCCESS' ? 'orange' : activeBatch.status === 'FAILED' || activeBatch.status === 'INTERRUPTED' ? 'red' : 'blue'}>{t(`batchUpgradeStatus_${activeBatch.status}`)}</Tag> : null}
      >
        {activeBatch ? (
          <>
            <Progress
              percent={activeBatch.total === 0 ? 100 : Math.round(((activeBatch.success + activeBatch.failed + activeBatch.skipped) / activeBatch.total) * 100)}
              status={activeBatch.status === 'FAILED' || activeBatch.status === 'INTERRUPTED' ? 'exception' : activeBatch.status === 'SUCCESS' ? 'success' : 'active'}
            />
            <Space wrap style={{ marginBottom: 16 }}>
              <Tag color="green">{t('batchUpgradeSuccess')}: {activeBatch.success}</Tag>
              <Tag color="red">{t('batchUpgradeFailed')}: {activeBatch.failed}</Tag>
              <Tag>{t('batchUpgradeSkipped')}: {activeBatch.skipped}</Tag>
            </Space>
            <Typography.Paragraph type="secondary">{t('batchUpgradeBackgroundHint')}</Typography.Paragraph>
            <List
              dataSource={activeBatch.items}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={`${item.node_id} · ${item.current_version ? `v${item.current_version}` : '-'} → ${item.target_version ? `v${item.target_version}` : '-'}`}
                    description={`${t(`batchUpgradeItemStatus_${item.status as BatchUpgradeItemStatus}`)}${item.reason ? ` · ${item.reason}` : ''}`}
                  />
                </List.Item>
              )}
            />
          </>
        ) : null}
      </Drawer>
      <Modal
        title={t('nodeUninstallConfirmTitle')}
        open={uninstallRow !== null}
        okText={t('nodeUninstall')}
        okButtonProps={{ danger: true, disabled: uninstallConfirmation !== 'UNINSTALL' }}
        cancelText={t('cancel')}
        onCancel={() => setUninstallRow(null)}
        onOk={async () => {
          if (!uninstallRow) return;
          const row = uninstallRow;
          setUninstallRow(null);
          await startOperation(row, 'uninstall', uninstallConfirmation);
        }}
      >
        <Typography.Paragraph>{t('nodeUninstallConfirm')}</Typography.Paragraph>
        <Input value={uninstallConfirmation} onChange={(event) => setUninstallConfirmation(event.target.value)} placeholder="UNINSTALL" />
      </Modal>
    </>
  );
}
