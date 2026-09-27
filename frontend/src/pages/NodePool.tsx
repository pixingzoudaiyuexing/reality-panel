import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Input, Modal, Space, Table, Tag, message } from 'antd';
import { CloudServerOutlined, EditOutlined, ReloadOutlined } from '@ant-design/icons';
import api from '../api/client';
import type { ApiEnvelope, PoolNode } from '../api/types';
import { useI18n } from '../i18n/context';
import { poolNodeKey, poolNodeName } from '../components/nodes/poolNodeName';

export default function NodePool() {
  const { t } = useI18n();
  const [nodes, setNodes] = useState<PoolNode[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [editing, setEditing] = useState<PoolNode | null>(null);
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.get<unknown, ApiEnvelope<PoolNode[]>>('/admin/node-pool/nodes');
      if (result.code !== 0 || !result.data) throw new Error('unavailable');
      setNodes(result.data);
      setFailed(false);
    } catch { setFailed(true); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);
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
  return <>
    <div className="rp-page-header">
      <h2 className="rp-page-title"><CloudServerOutlined /> {t('nodePool')}</h2>
      <Button icon={<ReloadOutlined />} onClick={() => void load()}>{t('refresh')}</Button>
    </div>
    {failed && <Alert type="error" showIcon title={t('poolLoadFailed')} />}
    <Table rowKey={poolNodeKey} dataSource={nodes} loading={loading} scroll={{ x: 800 }}
      columns={[
        { title: t('poolNodeName'), render: (_: unknown, node: PoolNode) => <span title={node.node_id}>{poolNodeName(node)}</span> },
        { title: 'IP', render: (_: unknown, node: PoolNode) => <Space orientation="vertical" size={0}><span>{node.public_ipv4 || '-'}</span><span>{node.public_ipv6}</span></Space> },
        { title: t('status'), render: (_: unknown, node: PoolNode) => <Tag color={node.online ? 'green' : undefined}>{t(node.online ? 'online' : 'offline')}</Tag> },
        { title: t('nodeVersion'), dataIndex: 'node_version', render: (value: string | null) => value || '-' },
        { title: t('poolMemberships'), render: (_: unknown, node: PoolNode) => node.memberships.map(m => <Tag key={m.group_id}>{m.group_name}</Tag>) },
        { title: t('lastSeen'), dataIndex: 'last_seen', render: (value: string | null) => value || '-' },
        { title: t('action'), render: (_: unknown, node: PoolNode) => <Button icon={<EditOutlined />} onClick={() => { setEditing(node); setName(node.display_name); }}>{t('edit')}</Button> },
      ]} />
    <Modal title={t('poolEditName')} open={!!editing} onCancel={() => setEditing(null)} onOk={() => void save()} confirmLoading={saving}>
      <Input aria-label={t('poolNodeName')} value={name} maxLength={128} onChange={e => setName(e.target.value)} />
    </Modal>
  </>;
}
