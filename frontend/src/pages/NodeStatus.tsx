import { useEffect, useMemo, useRef, useState } from 'react';
import { Spin, Result, Empty, Modal, message, Button, Drawer, Input, Tag, Typography, Space } from 'antd';
import { CloudUploadOutlined, CopyOutlined, LineChartOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import type { ApiEnvelope, DeviceGroup, ForwardRule, NodeStatus, SharedNodeSummary, NodeDisplayRow, NodeLifecycleAction, NodeOperation, NodeArtifactCatalog, RelayReadyNode } from '../api/types';
import { useI18n } from '../i18n/context';
import { useAuth } from '../auth/useAuth';
import { NodeGroupSection } from '../components/nodes/NodeGroupSection';
import { NodeDetailDrawer } from '../components/nodes/NodeDetailDrawer';
import { stableGroupedRows } from '../components/nodes/sort';
import { RuleDiagnosisModal } from '../components/diagnosis/RuleDiagnosisModal';

type AnyNodeRow = NodeDisplayRow;

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
 * users land here after login (via the sidebar). Admin reads /nodes; regular
 * users read /nodes/shared (server-side field filtering — the frontend never
 * hides sensitive fields client-side).
 */
export default function NodeStatus() {
  const { t } = useI18n();
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const isMobile = useIsMobile();

  const [adminRows, setAdminRows] = useState<NodeStatus[] | null>(null);
  const [userRows, setUserRows] = useState<SharedNodeSummary[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [artifactVersions, setArtifactVersions] = useState<Record<string, string>>({});
  const [panelProtocol, setPanelProtocol] = useState(0);
  const [inboundGroupIds, setInboundGroupIds] = useState<Set<number>>(() => new Set());
  const [detailRow, setDetailRow] = useState<AnyNodeRow | null>(null);
  const [activeOperation, setActiveOperation] = useState<NodeOperation | null>(null);
  const [uninstallRow, setUninstallRow] = useState<AnyNodeRow | null>(null);
  const [uninstallConfirmation, setUninstallConfirmation] = useState('');
  const [nodeDiagnosisRule, setNodeDiagnosisRule] = useState<ForwardRule | null>(null);
  const [nodeDiagnosisTarget, setNodeDiagnosisTarget] = useState<{ nodeId: string; nodeLabel: string } | null>(null);
  const [nodeDiagnosisCandidates, setNodeDiagnosisCandidates] = useState<ForwardRule[]>([]);
  const [nodeDiagnosisPickerOpen, setNodeDiagnosisPickerOpen] = useState(false);
  // Guards against overlapping polls: on a slow network (axios 10s timeout vs
  // 5s interval) a new tick could otherwise fire before the previous request
  // returned, stacking requests.
  const inFlightRef = useRef(false);
  const hasLoadedRowsRef = useRef(false);

  const loadAdmin = async () => {
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes');
      if (res.code !== 0) {
        if (!hasLoadedRowsRef.current) setLoadFailed(true);
        return;
      }
      setLoadFailed(false);
      setAdminRows(res.data || []);
      hasLoadedRowsRef.current = true;
    } catch {
      if (!hasLoadedRowsRef.current) setLoadFailed(true);
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

  // Poll node status every 5s. The version info is NOT polled — it's static
  // for the lifetime of a panel process, so it's fetched once on mount (admin
  // only). loadFailed is cleared only on a successful response (inside the
  // load* fns), so a transient poll failure no longer flashes the error page
  // back to stale data every 5s.
  useEffect(() => {
    hasLoadedRowsRef.current = false;
    if (isAdmin) loadLifecycleMetadata();
    refresh();
    const ti = setInterval(refresh, 5000);
    return () => clearInterval(ti);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  const errorMessage = (error: unknown) => {
    const payload = (error as { response?: { data?: { message?: string } } })?.response?.data;
    return payload?.message || t('nodeOperationFailed');
  };

  const copyLogs = async () => {
    if (!activeOperation?.logs) return;
    try {
      await navigator.clipboard.writeText(activeOperation.logs);
      message.success(t('copied'));
    } catch {
      message.error(t('copyFailed'));
    }
  };

  const pollOperation = async (row: AnyNodeRow, operationId: string) => {
    if (!row.node_id) return;
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeOperation>>(
        `/admin/nodes/${row.group_id}/${row.node_id}/operations/${operationId}`,
      );
      if (res.code !== 0 || !res.data) throw new Error(res.message);
      setActiveOperation(res.data);
      if (!['SUCCESS', 'FAILED', 'TIMEOUT'].includes(res.data.status)) {
        window.setTimeout(() => pollOperation(row, operationId), 1000);
      }
    } catch (error) {
      message.error(errorMessage(error));
    }
  };

  const startOperation = async (row: AnyNodeRow, action: NodeLifecycleAction, confirmation?: string) => {
    if (!row.node_id) return;
    try {
      const res = action === 'logs'
        ? await api.get<unknown, ApiEnvelope<NodeOperation>>(`/admin/nodes/${row.group_id}/${row.node_id}/logs?lines=200`)
        : await api.post<unknown, ApiEnvelope<NodeOperation>>(
            `/admin/nodes/${row.group_id}/${row.node_id}/operations/${action}`,
            confirmation ? { confirmation } : {},
          );
      if (res.code !== 0 || !res.data) { message.error(res.message); return; }
      setActiveOperation(res.data);
      void pollOperation(row, res.data.id);
    } catch (error) {
      message.error(errorMessage(error));
    }
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

  const handleDiagnoseNode = async (groupId: number, node: RelayReadyNode) => {
    const nodeId = node.node_id.trim();
    if (!nodeId) return;
    try {
      const response = await api.get<unknown, ApiEnvelope<ForwardRule[]>>('/rules');
      if (response.code !== 0 || !response.data) {
        message.error(response.message || t('diagnoseFailed'));
        return;
      }
      const candidates = response.data.filter((rule) => rule.device_group_in === groupId && rule.protocol !== 'udp');
      if (candidates.length === 0) {
        message.info(t('diagnosisNoTcpRuleForNode'));
        return;
      }
      setNodeDiagnosisTarget({ nodeId, nodeLabel: node.public_ipv4 ?? nodeId });
      if (candidates.length === 1) {
        setNodeDiagnosisRule(candidates[0]);
      } else {
        setNodeDiagnosisCandidates(candidates);
        setNodeDiagnosisPickerOpen(true);
      }
    } catch {
      message.error(t('diagnoseFailed'));
    }
  };

  const rows: AnyNodeRow[] | null = isAdmin ? adminRows : userRows;
  const groups = useMemo(() => (rows ? stableGroupedRows(rows) : null), [rows]);

  const title = t('nodeStatus');
  const pageTitle = (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
      <h2 className="rp-page-title"><LineChartOutlined /> {title}</h2>
      {isAdmin && <Button type="primary" icon={<CloudUploadOutlined />} onClick={() => navigate('/node-bootstrap')}>{t('nodeBootstrapTitle')}</Button>}
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
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/nodes/${row.group_id}${qs}`);
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
          onDiagnoseNode={isAdmin ? handleDiagnoseNode : undefined}
        />
      ))}
      <NodeDetailDrawer
        row={detailRow}
        open={detailRow !== null}
        onClose={() => setDetailRow(null)}
        isAdmin={isAdmin}
        panelProtocol={panelProtocol}
        onDeleted={refresh}
      />
      <Modal
        title={t('diagnosisSelectRule')}
        open={nodeDiagnosisPickerOpen}
        onCancel={() => setNodeDiagnosisPickerOpen(false)}
        footer={null}
      >
        <Space orientation="vertical" style={{ width: '100%' }}>
          {nodeDiagnosisCandidates.map((rule) => (
            <Button
              key={rule.id}
              block
              onClick={() => {
                setNodeDiagnosisRule(rule);
                setNodeDiagnosisPickerOpen(false);
              }}
            >
              #{rule.id} {rule.name} · :{rule.listen_port}{rule.sni ? ` · ${rule.sni}` : ''}
            </Button>
          ))}
        </Space>
      </Modal>
      <RuleDiagnosisModal
        rule={nodeDiagnosisRule}
        open={nodeDiagnosisRule !== null && nodeDiagnosisTarget !== null}
        onClose={() => {
          setNodeDiagnosisRule(null);
          setNodeDiagnosisTarget(null);
          setNodeDiagnosisCandidates([]);
        }}
        isAdmin={isAdmin}
        t={t}
        nodeId={nodeDiagnosisTarget?.nodeId}
        nodeLabel={nodeDiagnosisTarget?.nodeLabel}
      />
      <Drawer
        title={activeOperation ? t(`nodeOperation_${activeOperation.action}`) : t('nodeOperations')}
        open={activeOperation !== null}
        onClose={() => setActiveOperation(null)}
        width={isMobile ? '100%' : 640}
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
            <Tag color={activeOperation.status === 'SUCCESS' ? 'green' : activeOperation.status === 'FAILED' || activeOperation.status === 'TIMEOUT' ? 'red' : 'blue'}>{t(`nodeOperationStatus_${activeOperation.status}`)}</Tag>
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
