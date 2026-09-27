import { useEffect, useState } from 'react';
import { Alert, Space, Tag, Typography } from 'antd';
import api from '../../api/client';
import type { ApiEnvelope, NodeReuseRuntimeStatus, PoolNode } from '../../api/types';
import { useI18n } from '../../i18n/context';

export function GroupMembershipSummary({ homeGroupId, nodeId, open }: { homeGroupId: number; nodeId: string; open: boolean }) {
  const { t } = useI18n();
  const [node, setNode] = useState<PoolNode | null>(null);
  const [runtime, setRuntime] = useState<NodeReuseRuntimeStatus | null>(null);
  useEffect(() => {
    if (!open) return;
    let active = true;
    const load = async () => {
      try {
        const [pool, status] = await Promise.all([
          api.get<unknown, ApiEnvelope<PoolNode[]>>('/admin/node-pool/nodes'),
          api.get<unknown, ApiEnvelope<NodeReuseRuntimeStatus>>(`/admin/node-reuse/nodes/${homeGroupId}/${encodeURIComponent(nodeId)}/runtime-status`),
        ]);
        if (active) {
          setNode(Array.isArray(pool.data) ? pool.data.find(n => n.identity_group_id === homeGroupId && n.node_id === nodeId) || null : null);
          setRuntime(status.code === 0 && status.data && 'sync_state' in status.data ? status.data : null);
        }
      } catch { if (active) { setNode(null); setRuntime(null); } }
    };
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [homeGroupId, nodeId, open]);
  return <section style={{ marginTop: 20 }}>
    <Typography.Title level={5}>{t('poolMemberships')}</Typography.Title>
    <Space wrap>{node?.memberships.map(m => <Tag key={m.group_id}>{m.group_name}</Tag>)}</Space>
    {runtime && <Alert style={{ marginTop: 12 }} type={runtime.sync_state === 'SYNCED' ? 'success' : 'info'}
      title={t(`nodeReuseState_${runtime.sync_state}`)} />}
    <details style={{ marginTop: 12 }}>
      <summary>{t('nodeReuseAdvanced')}</summary>
      <div>{t('nodeReuseExpectedRevision')}: {runtime?.expected_revision ?? '-'}</div>
    </details>
  </section>;
}
