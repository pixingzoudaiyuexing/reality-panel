import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Collapse, Input, Modal, Select, Space, Tag, Typography } from 'antd';
import { ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type { ApiEnvelope, DeviceGroup, NodeOperation, NodeReusePreview, NodeReuseRuntimeStatus, PoolNode } from '../../api/types';
import { useI18n } from '../../i18n/context';
import { poolNodeKey, poolNodeName } from './poolNodeName';

type Migration = { claim: { claim_id: string; expires_at?: string }; claim_secret?: string | null; command: string; recovery?: boolean };
export function GroupPoolPicker({ group, onClose, onChanged }: { group: DeviceGroup; onClose: () => void; onChanged: () => void }) {
  const { t } = useI18n();
  const [nodes, setNodes] = useState<PoolNode[]>([]);
  const [selected, setSelected] = useState<string>();
  const [preview, setPreview] = useState<NodeReusePreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [migration, setMigration] = useState<Migration | null>(null);
  const [convergence, setConvergence] = useState<NodeOperation | null>(null);
  const [saved, setSaved] = useState(false);
  const [sync, setSync] = useState<NodeReuseRuntimeStatus | null>(null);
  const generation = useRef(0);
  const node = nodes.find(n => poolNodeKey(n) === selected);
  const identityGroupId = node?.identity_group_id;
  const nodeId = node?.node_id;
  const load = useCallback(async () => {
    try {
      const response = await api.get<unknown, ApiEnvelope<PoolNode[]>>('/admin/node-pool/nodes');
      if (response.code !== 0 || !response.data) throw new Error();
      setNodes(response.data);
    } catch { setError(t('poolLoadFailed')); }
  }, [t]);
  useEffect(() => { void load(); return () => { generation.current += 1; }; }, [load]);
  useEffect(() => {
    if (!identityGroupId || !nodeId || (!migration && !saved) || (migration && node?.safe_to_add && !saved)) return;
    let active = true;
    const refresh = async () => {
      if (migration && !saved) await load();
      if (saved) try {
        const response = await api.get<unknown, ApiEnvelope<NodeReuseRuntimeStatus>>(`/admin/node-reuse/nodes/${identityGroupId}/${encodeURIComponent(nodeId)}/runtime-status`);
        if (active && response.code === 0) setSync(response.data);
      } catch { if (active) setSync(null); }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [identityGroupId, nodeId, node?.safe_to_add, migration, saved, load]);
  useEffect(() => {
    if (!convergence || !identityGroupId || !nodeId || convergence.status === 'SUCCESS' || convergence.status === 'FAILED') return;
    let active = true;
    const refresh = async () => {
      try {
        const response = await api.get<unknown, ApiEnvelope<NodeOperation>>(
          `/admin/nodes/${identityGroupId}/${encodeURIComponent(nodeId)}/operations/${convergence.id}`,
        );
        if (active && response.code === 0 && response.data) {
          setConvergence(response.data);
          if (response.data.status === 'SUCCESS') await load();
        }
      } catch { if (active) setError(t('poolMigrationFailed')); }
    };
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [convergence, identityGroupId, nodeId, load, t]);
  const check = async () => {
    if (!node) return;
    const request = ++generation.current;
    setBusy(true); setPreview(null); setError(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<NodeReusePreview>>(`/admin/groups/${group.id}/nodes/preview`, { identity_group_id: node.identity_group_id, node_id: node.node_id });
      if (response.code !== 0 || !response.data) throw new Error();
      if (request === generation.current) setPreview(response.data);
    } catch { if (request === generation.current) setError(t('nodeReuseCheckFailed')); }
    finally { if (request === generation.current) setBusy(false); }
  };
  const add = async () => {
    if (!node?.safe_to_add || !preview?.known_runtime_prerequisites_satisfied || preview.conflicts.length) return;
    setBusy(true); setError(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<unknown>>(`/admin/groups/${group.id}/nodes`, { identity_group_id: node.identity_group_id, node_id: node.node_id });
      if (response.code !== 0) throw new Error();
      setSaved(true); onChanged();
    } catch { setPreview(null); setError(t('nodeReuseCheckFailed')); }
    finally { setBusy(false); }
  };
  const migrate = async () => {
    if (!node) return;
    const request = ++generation.current;
    setBusy(true); setError(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<Migration>>(`/admin/node-pool/nodes/${node.identity_group_id}/${encodeURIComponent(node.node_id)}/migration`);
      if (response.code !== 0 || !response.data?.command) throw new Error();
      if (request === generation.current) setMigration(response.data);
    } catch { if (request === generation.current) setError(t('poolMigrationFailed')); }
    finally { if (request === generation.current) setBusy(false); }
  };
  const converge = async () => {
    if (!node) return;
    setBusy(true); setError(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<NodeOperation>>(
        `/admin/node-pool/nodes/${node.identity_group_id}/${encodeURIComponent(node.node_id)}/identity-convergence`, {},
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setConvergence(response.data);
    } catch (cause) {
      const detail = (cause as { response?: { data?: { message?: string } } }).response?.data?.message;
      setError(detail === 'AMBIGUOUS_NODE_IDENTITY' ? t('poolIdentityConflict') : t('poolMigrationFailed'));
    } finally { setBusy(false); }
  };
  const cancelMigration = async () => {
    const claimId = migration?.claim.claim_id || node?.migration_claim_id;
    if (!claimId) return;
    setBusy(true);
    try {
      const result = await api.delete<unknown, ApiEnvelope<unknown>>(`/admin/node-credential-claims/${claimId}`);
      if (result.code !== 0) throw new Error();
      setMigration(null); await load();
    } catch { setError(t('poolMigrationFailed')); }
    finally { setBusy(false); }
  };
  const command = migration?.command || '';
  return <Modal open title={`${t('addNode')} · ${group.name}`} onCancel={onClose} footer={null}>
    <Space orientation="vertical" style={{ width: '100%' }}>
      {error && <Alert type="error" showIcon title={error} />}
      <Select aria-label={t('poolChooseNode')} showSearch style={{ width: '100%' }} disabled={saved || busy}
        value={selected} placeholder={t('poolChooseNode')}
        onChange={value => { generation.current += 1; setSelected(value); setPreview(null); setMigration(null); setConvergence(null); setError(null); }}
        options={nodes.map(n => ({ value: poolNodeKey(n), disabled: n.memberships.some(m => m.group_id === group.id),
          label: `${poolNodeName(n)} · ${n.public_ipv4 || n.public_ipv6 || '-'} · ${t(n.online ? 'online' : 'offline')}${n.memberships.some(m => m.group_id === group.id) ? ' · ' + t('poolAlreadyMember') : ''}` }))}
        filterOption={(input, option) => {
          const n = nodes.find(n => poolNodeKey(n) === option?.value);
          return !!n && [n.display_name, n.public_ipv4, n.public_ipv6, n.node_id].some(v => v?.toLowerCase().includes(input.toLowerCase()));
        }} />
      {!saved && node?.migration_required && <>
        <Alert type="info" showIcon title={t(node.migration_incomplete ? 'poolMigrationIncomplete' : 'poolMigrationRequired')}
          description={!node.auth_reload_supported ? t('poolUpgradeRequired') : undefined} />
        {!convergence && !node.migration_pending && <Button type="primary" loading={busy} onClick={() => void converge()}>
          {t('poolConvergeNode')}
        </Button>}
        {convergence && <Tag color={convergence.status === 'FAILED' ? 'red' : convergence.status === 'SUCCESS' ? 'green' : 'blue'}>
          {t(`poolConvergence_${convergence.convergence_phase ?? 'PREPARING_NODE'}`)}
        </Tag>}
        {node.migration_pending && !convergence && <Alert type="info" title={t('poolMigrationExistingPending')} />}
        <Collapse ghost items={[{ key: 'recovery', label: t('poolAdvancedRecovery'), children: <>
          {!migration && (node.recovery_available || !node.migration_pending) && <Button
            disabled={!node.recovery_available && !node.auth_reload_supported} loading={busy} onClick={() => void migrate()}>
            {t(node.recovery_available ? 'poolContinueMigration' : 'poolStartMigration')}
          </Button>}
          {!node.credential_active && (migration || node.migration_pending) && <Button loading={busy} onClick={() => void cancelMigration()}>{t('cancel')}</Button>}
          {migration && <>
            <Typography.Text>{t('poolMigrationPending')}</Typography.Text>
            <Typography.Paragraph copyable={{ text: command }}><code style={{ overflowWrap: 'anywhere' }}>{command}</code></Typography.Paragraph>
            {migration.claim_secret && <Input.Password readOnly value={migration.claim_secret} aria-label={t('poolMigrationSecret')} />}
            <Typography.Text type="secondary">{migration.claim.expires_at}</Typography.Text>
          </>}
        </> }]} />
      </>}
      {!saved && node && !node.safe_to_add && !node.migration_required && <Alert type="error" showIcon title={t('poolCredentialUnavailable')} />}
      {!saved && <Button icon={<SafetyCertificateOutlined />} disabled={!node?.safe_to_add} loading={busy} onClick={() => void check()}>{t('nodeReuseCheck')}</Button>}
      {!saved && preview && <>
        <Alert type={preview.conflicts.length ? 'error' : 'success'} showIcon
          title={t(preview.conflicts.length ? 'nodeReuseCheckBlocked' : 'nodeReuseCheckPassed')}
          description={preview.conflicts.length ? t('nodeReuseNoChangeNext') : t('nodeReuseImpact').replace('{groups}', String(preview.sources.length)).replace('{rules}', String(preview.sources.reduce((n, s) => n + s.rule_ids.length, 0)))} />
        <Button type="primary" disabled={!node?.safe_to_add || !preview.known_runtime_prerequisites_satisfied || !!preview.conflicts.length} loading={busy} onClick={() => void add()}>{t('addNode')}</Button>
      </>}
      {saved && <Alert type={sync?.sync_state === 'SYNCED' ? 'success' : 'info'} showIcon title={t('nodeReuseBindingSaved')}
        description={t(`nodeReuseState_${sync?.sync_state || 'WAITING'}`)} />}
      <Button icon={<ReloadOutlined />} onClick={() => void load()}>{t('refresh')}</Button>
    </Space>
  </Modal>;
}
