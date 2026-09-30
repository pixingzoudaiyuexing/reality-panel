import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Modal, Select, Space } from 'antd';
import { ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type { ApiEnvelope, DeviceGroup, NodeReusePreview, NodeReuseRuntimeStatus, PoolNode } from '../../api/types';
import { useI18n } from '../../i18n/context';
import { poolNodeKey, poolNodeName } from './poolNodeName';

export function GroupPoolPicker({ group, onClose, onChanged }: { group: DeviceGroup; onClose: () => void; onChanged: () => void }) {
  const { t } = useI18n();
  const [nodes, setNodes] = useState<PoolNode[]>([]);
  const [selected, setSelected] = useState<string>();
  const [preview, setPreview] = useState<NodeReusePreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [sync, setSync] = useState<NodeReuseRuntimeStatus | null>(null);
  const generation = useRef(0);
  const poolNodes = nodes.filter(n => n.pool_native);
  const node = poolNodes.find(n => poolNodeKey(n) === selected);
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
    if (!identityGroupId || !nodeId || !saved) return;
    let active = true;
    const refresh = async () => {
      try {
        const response = await api.get<unknown, ApiEnvelope<NodeReuseRuntimeStatus>>(`/admin/node-reuse/nodes/${identityGroupId}/${encodeURIComponent(nodeId)}/runtime-status`);
        if (active && response.code === 0) setSync(response.data);
      } catch { if (active) setSync(null); }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [identityGroupId, nodeId, saved]);
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
  return <Modal open title={`${t('addNode')} · ${group.name}`} onCancel={onClose} footer={null}>
    <Space orientation="vertical" style={{ width: '100%' }}>
      {error && <Alert type="error" showIcon title={error} />}
      <Select aria-label={t('poolChooseNode')} showSearch style={{ width: '100%' }} disabled={saved || busy}
        value={selected} placeholder={t('poolChooseNode')}
        onChange={value => { generation.current += 1; setSelected(value); setPreview(null); setError(null); }}
        options={poolNodes.map(n => ({ value: poolNodeKey(n), disabled: n.memberships.some(m => m.group_id === group.id),
          label: `${poolNodeName(n)} · ${n.public_ipv4 || n.public_ipv6 || '-'} · ${t(n.online ? 'online' : 'offline')}${n.memberships.some(m => m.group_id === group.id) ? ' · ' + t('poolAlreadyMember') : ''}` }))}
        filterOption={(input, option) => {
          const n = poolNodes.find(n => poolNodeKey(n) === option?.value);
          return !!n && [n.display_name, n.public_ipv4, n.public_ipv6, n.node_id].some(v => v?.toLowerCase().includes(input.toLowerCase()));
        }} />
      {!saved && node && !node.safe_to_add && <Alert type="error" showIcon title={t('poolCredentialUnavailable')} />}
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
