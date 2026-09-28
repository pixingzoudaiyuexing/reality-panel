import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Input, Modal, Space, Table, Tabs, Tag, Tooltip, message } from 'antd';
import { CloudServerOutlined, DeleteOutlined, EditOutlined, ReloadOutlined, RotateLeftOutlined } from '@ant-design/icons';
import api from '../api/client';
import type { ApiEnvelope, NodeHealthSnapshot, NodeRetirementPreview, PoolNode, RetiredPoolNode } from '../api/types';
import { useI18n } from '../i18n/context';
import { poolNodeKey, poolNodeName } from '../components/nodes/poolNodeName';
import type { Dict } from '../i18n/zh-CN';

function blockerLabel(code: string, t: (key: keyof Dict) => string): string {
  const [kind, detail] = code.split(':', 2);
  const labels: Record<string, keyof Dict> = {
    REUSE_MEMBERSHIP: 'poolBlocker_REUSE_MEMBERSHIP', ROUTING_REFERENCE: 'poolBlocker_ROUTING_REFERENCE',
    CARRIER_REFERENCE: 'poolBlocker_CARRIER_REFERENCE', ROUTING_TRANSACTION: 'poolBlocker_ROUTING_TRANSACTION',
    FAILOVER_REFERENCE: 'poolBlocker_FAILOVER_REFERENCE', FAILOVER_POLICY: 'poolBlocker_FAILOVER_POLICY',
    SCHEDULE_REFERENCE: 'poolBlocker_SCHEDULE_REFERENCE', BATCH_UPGRADE: 'poolBlocker_BATCH_UPGRADE',
    CREDENTIAL_CLAIM: 'poolBlocker_CREDENTIAL_CLAIM', CREDENTIAL_DELIVERY: 'poolBlocker_CREDENTIAL_DELIVERY',
    LIFECYCLE_OPERATION: 'poolBlocker_LIFECYCLE_OPERATION',
    IDENTITY_CONVERGENCE: 'poolBlocker_IDENTITY_CONVERGENCE',
  };
  return `${labels[kind] ? t(labels[kind]) : kind}${detail ? ` (${detail})` : ''}`;
}

export default function NodePool() {
  const { t } = useI18n();
  const [nodes, setNodes] = useState<PoolNode[]>([]);
  const [health, setHealth] = useState<NodeHealthSnapshot[] | null>(null);
  const healthInFlight = useRef(false);
  const [retired, setRetired] = useState<RetiredPoolNode[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [retiredFailed, setRetiredFailed] = useState(false);
  const [editing, setEditing] = useState<PoolNode | null>(null);
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<NodeRetirementPreview | null>(null);
  const [retiring, setRetiring] = useState(false);
  const [confirmId, setConfirmId] = useState('');
  const [reason, setReason] = useState('');
  const [confirmOnline, setConfirmOnline] = useState(false);
  const [restoring, setRestoring] = useState<RetiredPoolNode | null>(null);
  const [restoreId, setRestoreId] = useState('');
  const [tab, setTab] = useState('active');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.get<unknown, ApiEnvelope<PoolNode[]>>('/admin/node-pool/nodes');
      if (result.code !== 0 || !result.data) throw new Error('unavailable');
      setNodes(result.data);
      setFailed(false);
    } catch { setFailed(true); }
    try {
      const result = await api.get<unknown, ApiEnvelope<RetiredPoolNode[]>>('/admin/node-pool/retired');
      if (result.code !== 0 || !result.data) throw new Error('retired unavailable');
      setRetired(result.data);
      setRetiredFailed(false);
    } catch { setRetiredFailed(true); }
    setLoading(false);
  }, []);
  useEffect(() => { void load(); }, [load]);
  const refreshHealth = useCallback(async () => {
    if (healthInFlight.current) return;
    healthInFlight.current = true;
    try {
      const result = await api.get<unknown, ApiEnvelope<NodeHealthSnapshot[]>>('/admin/node-health');
      const snapshots = result.data;
      setHealth(result.code === 0 && Array.isArray(snapshots)
        && snapshots.every((node) => node && typeof node.state === 'string' && node.telemetry
          && typeof node.telemetry.fresh === 'boolean') ? snapshots : null);
    } catch { setHealth(null); }
    finally { healthInFlight.current = false; }
  }, []);
  useEffect(() => {
    void refreshHealth();
    const timer = window.setInterval(() => void refreshHealth(), 5000);
    const onFocus = () => void refreshHealth();
    const onVisibility = () => { if (document.visibilityState === 'visible') void refreshHealth(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [refreshHealth]);
  const healthByIdentity = new Map((health ?? []).map((node) => [poolNodeKey(node), node]));
  const currentNodes = nodes.map((node) => {
    const snapshot = healthByIdentity.get(poolNodeKey(node));
    return snapshot ? {
      ...node,
      public_ipv4: snapshot.telemetry.public_ipv4,
      public_ipv6: snapshot.telemetry.public_ipv6,
      online: snapshot.telemetry.fresh,
      node_version: snapshot.telemetry.node_version,
      last_seen: snapshot.telemetry.last_seen,
    } : node;
  });

  const save = async () => {
    if (!editing) return;
    setSaving(true);
    try {
      const result = await api.patch<unknown, ApiEnvelope<null>>(
        `/admin/node-pool/nodes/${editing.identity_group_id}/${encodeURIComponent(editing.node_id)}`,
        { display_name: name.trim() },
      );
      if (result.code !== 0) throw new Error('rename failed');
      setEditing(null);
      await load();
    } catch { message.error(t('poolSaveFailed')); }
    finally { setSaving(false); }
  };

  const openRetirement = async (node: PoolNode) => {
    try {
      const result = await api.get<unknown, ApiEnvelope<NodeRetirementPreview>>(
        `/admin/node-pool/nodes/${node.identity_group_id}/${encodeURIComponent(node.node_id)}/retirement-preview`,
      );
      if (result.code !== 0 || !result.data) throw new Error('preview failed');
      setConfirmId(''); setReason(''); setConfirmOnline(false); setPreview(result.data);
    } catch { message.error(t('poolRetireFailed')); }
  };

  const retireNode = async () => {
    if (!preview) return;
    setRetiring(true);
    try {
      const result = await api.post<unknown, ApiEnvelope<null>>(
        `/admin/node-pool/nodes/${preview.identity_group_id}/${encodeURIComponent(preview.node_id)}/retire`,
        { expected_version: preview.retirement_version, confirm_node_id: confirmId,
          confirm_online: confirmOnline, reason: reason.trim() },
      );
      if (result.code !== 0) throw new Error('retirement rejected');
      setPreview(null);
      await load();
    } catch { message.error(t('poolRetireFailed')); }
    finally { setRetiring(false); }
  };

  const restoreNode = async () => {
    if (!restoring) return;
    setSaving(true);
    try {
      const result = await api.post<unknown, ApiEnvelope<null>>(
        `/admin/node-pool/nodes/${restoring.identity_group_id}/${encodeURIComponent(restoring.node_id)}/restore`,
        { expected_version: restoring.retirement_version, confirm_node_id: restoreId },
      );
      if (result.code !== 0) throw new Error('restore rejected');
      setRestoring(null);
      await load();
    } catch { message.error(t('poolRestoreFailed')); }
    finally { setSaving(false); }
  };

  return <>
    <div className="rp-page-header">
      <h2 className="rp-page-title"><CloudServerOutlined /> {t('nodePool')}</h2>
      <Button icon={<ReloadOutlined />} onClick={() => void load()}>{t('refresh')}</Button>
    </div>
    {failed && <Alert type="error" showIcon title={t('poolLoadFailed')} />}
    <Tabs activeKey={tab} onChange={setTab} items={[
      { key: 'active', label: t('poolActive'), children: <Table rowKey={poolNodeKey} dataSource={currentNodes} loading={loading} scroll={{ x: 880 }}
        columns={[
          { title: t('poolNodeName'), render: (_: unknown, node: PoolNode) => <span title={node.node_id}>{poolNodeName(node)}</span> },
          { title: 'IP', render: (_: unknown, node: PoolNode) => <Space orientation="vertical" size={0}><span>{node.public_ipv4 || '-'}</span><span>{node.public_ipv6}</span></Space> },
          { title: t('status'), render: (_: unknown, node: PoolNode) => {
            const state = healthByIdentity.get(poolNodeKey(node))?.state ?? 'UNKNOWN';
            return <Tag color={{ HEALTHY: 'green', DEGRADED: 'gold', OFFLINE: 'default', UNKNOWN: 'default' }[state]}>{t(`nodeHealth_${state}`)}</Tag>;
          } },
          { title: t('nodeVersion'), dataIndex: 'node_version', render: (value: string | null) => value || '-' },
          { title: t('poolMemberships'), render: (_: unknown, node: PoolNode) => node.memberships.map(m => <Tag key={m.group_id}>{m.group_name}</Tag>) },
          { title: t('lastSeen'), dataIndex: 'last_seen', render: (value: string | null) => value || '-' },
          { title: t('action'), render: (_: unknown, node: PoolNode) => <Space>
            <Tooltip title={t('edit')}><Button icon={<EditOutlined />} aria-label={t('edit')} onClick={() => { setEditing(node); setName(node.display_name); }} /></Tooltip>
            <Tooltip title={t('poolRetire')}><Button danger icon={<DeleteOutlined />} aria-label={t('poolRetire')} onClick={() => void openRetirement(node)} /></Tooltip>
          </Space> },
        ]} /> },
      { key: 'retired', label: t('poolRetired'), children: <>{retiredFailed && <Alert type="error" showIcon title={t('poolRetiredLoadFailed')} />}<Table rowKey={poolNodeKey} dataSource={retiredFailed ? [] : retired} loading={loading} scroll={{ x: 640 }}
        columns={[
          { title: t('poolNodeName'), render: (_: unknown, node: RetiredPoolNode) => node.display_name || node.node_id.slice(0, 12) },
          { title: 'Node ID', dataIndex: 'node_id', render: (id: string) => <span title={id}>{id}</span> },
          { title: t('poolRetireReason'), dataIndex: 'retirement_reason' },
          { title: t('lastSeen'), dataIndex: 'retired_at' },
          { title: t('action'), render: (_: unknown, node: RetiredPoolNode) => <Button icon={<RotateLeftOutlined />} onClick={() => { setRestoring(node); setRestoreId(''); }}>{t('poolRestore')}</Button> },
        ]} /></> },
    ]} />
    <Modal title={t('poolEditName')} open={!!editing} onCancel={() => setEditing(null)} onOk={() => void save()} confirmLoading={saving}>
      <Input aria-label={t('poolNodeName')} value={name} maxLength={128} onChange={e => setName(e.target.value)} />
    </Modal>
    <Modal title={t('poolRetire')} open={!!preview} onCancel={() => setPreview(null)} onOk={() => void retireNode()}
      okButtonProps={{ danger: true, disabled: !preview || preview.blockers.length > 0 || confirmId !== preview.node_id || !reason.trim() || (preview.online || preview.control_connected) && !confirmOnline }} confirmLoading={retiring}>
      {preview && <Space orientation="vertical" style={{ width: '100%' }} size={12}>
        <Descriptions size="small" column={1} items={[
          { key: 'name', label: t('poolNodeName'), children: preview.display_name || preview.public_ipv4 || preview.public_ipv6 || preview.node_id.slice(0, 12) },
          { key: 'ip', label: 'IP', children: [preview.public_ipv4, preview.public_ipv6].filter(Boolean).join(' / ') || '-' },
          { key: 'id', label: 'Node ID', children: preview.node_id },
          { key: 'seen', label: t('lastSeen'), children: preview.last_seen || '-' },
          { key: 'groups', label: t('poolMemberships'), children: preview.memberships.map(group => group.group_name).join(', ') || '-' },
        ]} />
        {preview.blockers.length > 0 && <Alert type="error" showIcon title={t('poolRetireBlocked')} description={preview.blockers.map(code => <div key={code}>{blockerLabel(code, t)}</div>)} />}
        {preview.warnings.includes('LEGACY_TOKEN_CANNOT_REVOKE_PHYSICAL_NODE') && <Alert type="warning" showIcon title={t('poolRetireLegacyWarning')} />}
        {(preview.online || preview.control_connected) && <><Alert type="warning" showIcon title={t('poolRetireOnlineWarning')} /><Checkbox checked={confirmOnline} onChange={event => setConfirmOnline(event.target.checked)}>{t('poolRetireOnlineConfirm')}</Checkbox></>}
        <Input.TextArea aria-label={t('poolRetireReason')} placeholder={t('poolRetireReason')} value={reason} maxLength={500} onChange={event => setReason(event.target.value)} />
        <Input aria-label={t('poolRetireConfirmId')} placeholder={t('poolRetireConfirmId')} value={confirmId} onChange={event => setConfirmId(event.target.value)} />
      </Space>}
    </Modal>
    <Modal title={t('poolRestore')} open={!!restoring} onCancel={() => setRestoring(null)} onOk={() => void restoreNode()}
      okButtonProps={{ disabled: !restoring || restoreId !== restoring.node_id }} confirmLoading={saving}>
      <Alert type="warning" showIcon title={t('poolRestoreWarning')} style={{ marginBottom: 12 }} />
      <Input aria-label={t('poolRetireConfirmId')} placeholder={t('poolRetireConfirmId')} value={restoreId} onChange={event => setRestoreId(event.target.value)} />
    </Modal>
  </>;
}
