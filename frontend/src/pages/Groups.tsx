import { Table, Button, Modal, Form, Input, InputNumber, Select, Space, message, Popconfirm, Typography, Tag, Tooltip, Alert, Switch, Card, Empty, Spin, Drawer } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, CloudServerOutlined, ApiOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, DeviceGroup, User, NodeDisplayRow as NodeStatus, PoolNode } from '../api/types';
import { useI18n } from '../i18n/context';
import { useAuth } from '../auth/useAuth';
import { RelayPreferencePanel } from '../components/nodes/RelayPreferencePanel';
import { GroupPoolPicker } from '../components/nodes/GroupPoolPicker';
import NodeStatusPage from './NodeStatus';
import { NodeDiagnosisDrawer } from '../components/diagnosis/NodeDiagnosisDrawer';
import { NodeResourcesCell, NodeConnectionsCell, NodeTrafficCell } from '../components/nodes/NodeStatusCells';
import { poolNodeName, poolNodeKey } from '../components/nodes/poolNodeName';

const { Text } = Typography;

/** v1.2.5: the forwarding/visibility columns and fields that a monitor-only
 *  group has no use for. It carries no rules and never reaches a regular user,
 *  so connect host, port range, rate and hidden are all inert on it. */
function isMonitorOnly(g: { group_type: string }): boolean {
  return g.group_type === 'monitor';
}

function usesConnectHost(g: { group_type: string }): boolean {
  return g.group_type === 'out';
}

const dash = <span style={{ color: 'var(--rp-text-tertiary)' }}>-</span>;

export default function Groups({ cards = false }: { cards?: boolean } = {}) {
  const { t } = useI18n();
  const [expandedCard, setExpandedCard] = useState<number | null>(null);
  const [groupSearch, setGroupSearch] = useState('');
  const [inspecting, setInspecting] = useState<string | null>(null);
  const [diagnosis, setDiagnosis] = useState<{ groupId: number; nodeId: string; label: string } | null>(null);
  const [groupsFailed, setGroupsFailed] = useState(false);
  const { isAdmin } = useAuth();
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [nodes, setNodes] = useState<NodeStatus[]>([]);
  const [poolNodes, setPoolNodes] = useState<PoolNode[]>([]);
  const [poolFailed, setPoolFailed] = useState(false);
  const [poolOpen, setPoolOpen] = useState(false);
  const [poolGroup, setPoolGroup] = useState<DeviceGroup | null>(null);
  const [loading, setLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editing, setEditing] = useState<DeviceGroup | null>(null);
  // v1.2.3: node-token rotation. `rotating` is the target group; `confirmName`
  // is the typed group name that unlocks the button — rotation kicks every node
  // in the group offline until each is re-enrolled, so it must not be one
  // careless click away.
  const [rotating, setRotating] = useState<DeviceGroup | null>(null);
  const [confirmName, setConfirmName] = useState('');
  const [rotateBusy, setRotateBusy] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();

  // v1.2.5: a monitor-only group reports node status to admins and nothing
  // else — no forwarding rule is ever bound to it, and list_shared_groups
  // filters to group_type='in', so it never reaches a regular user's lines or
  // node-status page either. Connect host, port range, rate and hidden are all
  // dead for it, so the forms stop asking. Hidden rather than disabled: a
  // greyed-out field still takes up the space and sends you looking for what
  // would enable it, when the honest answer is that it does not apply at all.
  const createType = Form.useWatch('group_type', createForm) ?? 'in';
  const editType = Form.useWatch('group_type', editForm) ?? editing?.group_type;
  const createIsMonitor = createType === 'monitor';
  const editIsMonitor = editType === 'monitor';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const g = await api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups');
      if (g.code !== 0 || !g.data) throw new Error('groups unavailable');
      setGroups(g.data);
      setGroupsFailed(false);
      if (isAdmin) {
        try {
          const u = await api.get<unknown, ApiEnvelope<User[]>>('/admin/users');
          setUsers(u.data || []);
        } catch { setUsers([]); }
        // v1.0.4: fetch node status for expandable node lists.
        try {
          const n = await api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes');
          setNodes(n.data || []);
        } catch { setNodes([]); }
        try {
          const pool = await api.get<unknown, ApiEnvelope<PoolNode[]>>('/admin/node-pool/nodes');
          if (pool.code !== 0 || !pool.data) throw new Error();
          setPoolNodes(pool.data || []);
          setPoolFailed(false);
        } catch { setPoolFailed(true); }
      } else {
        setUsers([]);
        try {
          const n = await api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes/shared');
          setNodes(n.data || []);
        } catch { setNodes([]); }
      }
    } catch { setGroupsFailed(true); } finally { setLoading(false); }
  }, [isAdmin]);

  useEffect(() => { load(); }, [load]);

  // ── Node helpers ──
  const nodesByGroup = useCallback((groupId: number): NodeStatus[] => {
    if (isAdmin) {
      const members = poolNodes.filter(node => node.memberships.some(member => member.group_id === groupId));
      const mapped = members.map(node => ({
        ...nodes.find(report => report.group_id === node.identity_group_id && report.node_id === node.node_id),
        ...node, group_id: groupId, last_seen: node.last_seen || '',
      } as NodeStatus));
      // Pool membership is authoritative for business groups. Never turn a
      // stale business-group report into an extra member of a reused Node.
      // Monitor and anonymous legacy status rows have no such Pool requirement.
      const monitor = groups.some(group => group.id === groupId && group.group_type === 'monitor');
      return [...mapped, ...nodes.filter(report => report.group_id === groupId && (monitor || !report.node_id) && !members.some(node => node.identity_group_id === report.group_id && node.node_id === report.node_id))];
    }
    return nodes.filter(n => n.group_id === groupId);
  }, [isAdmin, nodes, poolNodes, groups]);

  const openPool = (group: DeviceGroup) => { setPoolGroup(group); setPoolOpen(true); };
  const removeMember = async (groupId: number, node: PoolNode) => {
    try {
      const response = await api.delete<unknown, ApiEnvelope<unknown>>(`/admin/groups/${groupId}/nodes/${node.identity_group_id}/${encodeURIComponent(node.node_id)}`);
      if (response.code !== 0) throw new Error();
      message.info(t(node.online ? 'nodeReuseRemovedWaiting' : 'nodeReuseRemovedOffline'));
      await load();
    } catch { message.error(t('nodeReuseRemoveFailed')); }
  };

  const nodeCount = useCallback((groupId: number) => nodesByGroup(groupId).length, [nodesByGroup]);
  const onlineCount = useCallback((groupId: number) => nodesByGroup(groupId).filter(n => n.online).length, [nodesByGroup]);

  const handleCreate = async (values: { name: string; group_type: string; connect_host: string; port_range: string; rate?: number; hidden?: boolean; owner_uid?: number | null }) => {
    try {
      // v1.0.8: rate defaults to 1.0 on the server when omitted; send it
      // explicitly so the value the admin picked is what gets persisted.
      const payload = { ...values, rate: values.rate ?? 1.0, hidden: values.hidden ?? false, owner_uid: values.owner_uid || undefined };
      // v1.2.5: a monitor-only group forwards nothing, so the forwarding fields
      // are neutralised explicitly.
      //
      // Not merely cosmetic: hiding the Form.Items unregisters them, so `values`
      // arrives with no connect_host/port_range at all — and CreateGroupRequest
      // declares both as plain `String` with no serde default, which makes an
      // omission a 422 rather than an empty string. Empty IS a first-class value
      // for both columns (`NOT NULL DEFAULT ''`, and resolve_auto_port_range
      // reads empty as the default pool), so send it.
      if (values.group_type === 'monitor') {
        payload.connect_host = '';
        payload.port_range = '';
        payload.rate = 1.0;
        payload.hidden = false;
      } else if (values.group_type === 'in') {
        payload.connect_host = '';
      }
      const res = await api.post<unknown, ApiEnvelope<DeviceGroup>>('/groups', payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      load();
    } catch { message.error(t('failedCreateGroup')); }
  };

  const handleEdit = (g: DeviceGroup) => {
    setEditing(g);
    editForm.setFieldsValue({ name: g.name, group_type: g.group_type, connect_host: g.connect_host, port_range: g.port_range, rate: g.rate, hidden: !!g.hidden });
    setEditOpen(true);
  };

  const handleUpdate = async (values: { name?: string; group_type?: string; connect_host?: string; port_range?: string; rate?: number; hidden?: boolean }) => {
    if (!editing) return;
    const payload: Record<string, unknown> = {};
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.group_type !== undefined && values.group_type !== editing.group_type) payload.group_type = values.group_type;
    // v1.2.5: converting a group to monitor-only must leave its stored
    // forwarding fields ALONE. They do nothing while the group is a monitor,
    // but wiping them would destroy what you need to convert it back, and
    // "switch the type to look at something, switch it back" has to be a safe
    // round trip. No special case is needed here: hiding those Form.Items
    // unregisters them, so they arrive undefined and the `!== undefined` guards
    // below already skip them. Groups.test.tsx pins that round trip.
    if (values.group_type === 'in' && editing.connect_host !== '') {
      payload.connect_host = '';
    } else if (values.connect_host !== undefined && values.connect_host !== editing.connect_host) {
      payload.connect_host = values.connect_host;
    }
    if (values.port_range !== undefined && values.port_range !== editing.port_range) payload.port_range = values.port_range;
    // v1.0.8: only send rate when it actually changed (avoid no-op 400s and
    // keep the diff-based payload pattern used for the other fields).
    if (values.rate !== undefined && values.rate !== editing.rate) payload.rate = values.rate;
    // v1.0.7: only send hidden when it actually changed.
    if (values.hidden !== undefined && values.hidden !== !!editing.hidden) payload.hidden = values.hidden;
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/groups/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupUpdated'));
      setEditOpen(false);
      load();
    } catch { message.error(t('failedUpdateGroup')); }
  };

  const handleDelete = async (id: number) => {
    try {
      await api.delete(`/groups/${id}`);
      message.success(t('groupDeleted'));
      load();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { code?: number; message?: string } } };
      if (err?.response?.data?.code === 409) {
        message.error(err.response.data.message || t('groupInUse'));
      } else {
        message.error(t('failedDeleteGroup'));
      }
    }
  };

  /**
   * Rotate the group's node token. The backend invalidates the old token and
   * force-closes this group's live WS connections (a node that reconnected with
   * the revoked token used to fetch an empty config and tear down all its
   * listeners), so every node here is offline until re-enrolled.
   *
   * Manual and SSH Bootstrap obtain the new group token only inside their
   * protected provisioning bundle; the Groups page never renders it.
   */
  const handleRotateToken = async () => {
    if (!rotating) return;
    setRotateBusy(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<unknown>>(
        `/groups/${rotating.id}/rotate-token`,
      );
      if (res.code !== 0) { message.error(res.message || t('tokenRotateFailed')); return; }
      setRotating(null);
      setConfirmName('');
      load();
      message.success(t('tokenRotated'));
    } catch {
      message.error(t('tokenRotateFailed'));
    } finally {
      setRotateBusy(false);
    }
  };

  const typeColor = (gt: string) => {
    switch (gt) {
      case 'in': return 'green';
      case 'out': return 'cyan';
      case 'monitor': return 'default';
      default: return 'default';
    }
  };

  /**
   * v1.2.5: the type column's label.
   *
   * `in` / `out` / `monitor` are wire values, not something to show an operator
   * — the column rendered `gt.toUpperCase()`, so it read "IN" / "MONITOR" on an
   * otherwise Chinese page. Reuses the same strings as the form's picker, so
   * the label an admin picked is the label the row shows back.
   *
   * An unrecognised value falls back to the raw string rather than an empty
   * tag, so a type added on the backend before its label lands still reads.
   */
  const typeLabel = (gt: string) => {
    switch (gt) {
      case 'in': return t('inboundListener');
      case 'out': return t('outboundEgress');
      case 'monitor': return t('typeMonitor');
      default: return gt;
    }
  };

  // v1.0.4: create form only shows in/monitor (no out/egress).
  // v1.0.9: the edit form uses the same set — outbound/egress groups are no
  // longer offered anywhere in the UI.
  const groupTypeOptions = [
    { value: 'in', label: t('inboundListener') },
    { value: 'monitor', label: t('typeMonitor') },
  ];

  const columns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    { title: t('name'), dataIndex: 'name', key: 'name' },
    {
      title: t('type'), dataIndex: 'group_type', key: 'group_type',
      render: (gt: string) => <Tag color={typeColor(gt)}>{typeLabel(gt)}</Tag>,
    },
    {
      title: t('nodes'), key: 'nodes', width: 100,
      render: (_: unknown, g: DeviceGroup) => {
        const total = nodeCount(g.id);
        const online = onlineCount(g.id);
        return <span>{total > 0 ? `${online}/${total}` : '-'}</span>;
      },
    },
    // Reality inbound resolves its Relay IP from node telemetry, while monitor
    // groups do not forward at all. Only legacy outbound groups display their
    // stored connect_host; the column remains for those existing rows.
    { title: t('connectHost'), dataIndex: 'connect_host', key: 'connect_host', render: (v: string, g: DeviceGroup) => usesConnectHost(g) ? <span className="rp-mono">{v}</span> : dash },
    { title: t('portRange'), dataIndex: 'port_range', key: 'port_range', render: (v: string, g: DeviceGroup) => isMonitorOnly(g) ? dash : <span className="rp-mono">{v}</span> },
    {
      // v1.0.8: billing rate. Only show a tag when it differs from 1.0 — a 1x
      // column on every row is noise. The tag color reflects the multiplier
      // direction (gold = premium line, no tag = bill-as-used).
      title: t('rate'), dataIndex: 'rate', key: 'rate', width: 80,
      render: (rate: number, g: DeviceGroup) => {
        if (isMonitorOnly(g)) return dash;
        const r = typeof rate === 'number' ? rate : 1.0;
        if (Math.abs(r - 1.0) < 1e-9) return <span style={{ color: 'var(--rp-text-tertiary)' }}>1x</span>;
        // Trim trailing zeros: 2.0 → "2x", 1.5 → "1.5x".
        const label = Number.isInteger(r) ? `${r}x` : `${r}x`;
        return <Tag color="gold">{label}</Tag>;
      },
    },
    {
      // v1.0.7: hidden flag — only tag when hidden, to keep the column quiet.
      title: t('groupHidden'), dataIndex: 'hidden', key: 'hidden', width: 80,
      render: (hidden: boolean, g: DeviceGroup) =>
        hidden && !isMonitorOnly(g) ? <Tag>{t('yes')}</Tag> : dash,
    },
    {
      title: t('action'), key: 'action', width: 230,
      render: (_: unknown, g: DeviceGroup) => (
        <Space size={0}>
          {isAdmin && (
            <Tooltip title={t('addNode')}>
              {g.group_type === 'in' && <Button size="small" type="text" icon={<ApiOutlined />} onClick={() => openPool(g)} aria-label={t('addNode')} />}
            </Tooltip>
          )}
          <Button size="small" type="text" icon={<EditOutlined />} onClick={() => handleEdit(g)}>{t('edit')}</Button>
          <Tooltip title={t('rotateTokenHint')}>
            <Button
              size="small"
              type="text"
              icon={<SafetyCertificateOutlined />}
              onClick={() => { setConfirmName(''); setRotating(g); }}
            >
              {t('rotateToken')}
            </Button>
          </Tooltip>
          <Popconfirm title={t('deleteGroupConfirm')} onConfirm={() => handleDelete(g.id)}>
            <Button danger size="small" type="text">{t('delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const expandedRowRender = (g: DeviceGroup) => {
    const groupNodes = nodesByGroup(g.id);
    const routingPanel = isAdmin && g.group_type === 'in'
      ? <RelayPreferencePanel onDiagnoseNode={node => setDiagnosis({ groupId: g.id, nodeId: node.node_id, label: node.public_ipv4 || node.node_id })} key={groupNodes.map(node => poolNodeKey(node as unknown as PoolNode)).sort().join('|')} groupId={g.id} t={t} />
      : null;
    if (groupNodes.length === 0) {
      return (
        <div style={{ padding: '8px 0', color: 'var(--rp-text-tertiary)', fontSize: 13 }}>
          {t('noNodesInGroup')}
          {isAdmin && g.group_type === 'in' && <Button size="small" type="link" icon={<ApiOutlined />} style={{ marginLeft: 12 }} onClick={() => openPool(g)}>{t('addNode')}</Button>}
          {routingPanel}
        </div>
      );
    }
    return (
      <div style={{ padding: 4 }}>
        <div style={{ marginBottom: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>{t('nodesInGroup')} ({groupNodes.length})</Text>
          {isAdmin && g.group_type === 'in' && <Button size="small" icon={<ApiOutlined />} onClick={() => openPool(g)}>{t('addNode')}</Button>}
        </div>
        <Table
          dataSource={groupNodes}
          rowKey={(n: NodeStatus) => 'identity_group_id' in n ? poolNodeKey(n as unknown as PoolNode) : n.node_id ?? `${n.public_ipv4 ?? n.public_ip}-${n.last_seen}`}
          pagination={false}
          size="small"
          columns={[
            { title: t('poolNodeName'), key: 'name', width: 150, render: (_: unknown, n: NodeStatus) => <Button type="link" onClick={() => setInspecting('identity_group_id' in n ? poolNodeKey(n as unknown as PoolNode) : `${n.group_id}:${n.node_id || ''}`)}>{isAdmin && 'identity_group_id' in n ? poolNodeName(n as unknown as PoolNode) : n.group_name || n.public_ipv4 || n.public_ipv6 || '-'}</Button> },
            { title: 'IP', key: 'ip', render: (_: unknown, n: NodeStatus) => <Space orientation="vertical" size={0}><span>{n.public_ipv4 || n.public_ip || '-'}</span><span>{n.public_ipv6}</span></Space> },
            { title: t('status'), dataIndex: 'online', key: 'online', width: 80, render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? t('online') : t('offline')}</Tag> },
            { title: t('nodeVersion'), dataIndex: 'node_version', key: 'version', width: 90, render: (v: string | undefined) => v ? <span className="rp-mono" style={{ fontSize: 12 }}>{v}</span> : '-' },
            ...(cards ? [{ title: t('nodeResources'), key: 'resources', render: (_: unknown, node: NodeStatus) => <NodeResourcesCell row={node} t={t} /> }, { title: 'TCP / UDP', key: 'connections', render: (_: unknown, node: NodeStatus) => <NodeConnectionsCell row={node} /> }, { title: t('traffic'), key: 'traffic', render: (_: unknown, node: NodeStatus) => <NodeTrafficCell row={node} /> }] : []),
            { title: t('lastSeen'), dataIndex: 'last_seen', key: 'last_seen', width: 120, render: (v: string | undefined) => v ? <span style={{ fontSize: 12 }}>{v}</span> : '-' },
            ...(isAdmin ? [{ title: t('action'), key: 'remove', render: (_: unknown, n: NodeStatus) => {
              const node = n as unknown as PoolNode;
              if (!('identity_group_id' in n) || node.identity_group_id === g.id) return null;
              return <Popconfirm title={t('nodeReuseRemoveConfirm')} description={t(node.online ? 'nodeReuseRemoveImpact' : 'nodeReuseRemovedOffline')} onConfirm={() => removeMember(g.id, node)}>
                <Button danger size="small">{t('nodeReuseRemove')}</Button>
              </Popconfirm>;
            } }] : []),
          ]}
        />
        {routingPanel}
      </div>
    );
  };

  const visibleGroups = groups.filter(group => group.name.toLowerCase().includes(groupSearch.trim().toLowerCase()));

  return (
    <>
      {groupsFailed && <Alert type="error" showIcon title={t('loadFailed')} description={t('loadFailedRetry')} action={<Button onClick={() => void load()}>{t('retry')}</Button>} />}
      {isAdmin && poolFailed && <Alert type="error" showIcon title={t('poolLoadFailed')} />}
      {isAdmin && poolGroup && poolOpen && <GroupPoolPicker group={poolGroup} onClose={() => setPoolOpen(false)} onChanged={load} />}
      <div className="rp-page-header">
        {!cards && <h2 className="rp-page-title"><CloudServerOutlined /> {t('deviceGroups')}</h2>}
        <Space>
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>{t('addGroup')}</Button>
        </Space>
      </div>
      {cards ? <>
        <Input aria-label={t('groupsSearch')} placeholder={t('groupsSearch')} value={groupSearch} allowClear onChange={event => setGroupSearch(event.target.value)} style={{ maxWidth: 340, marginBottom: 16 }} />
        {loading ? <Spin /> : visibleGroups.length === 0 ? (groupsFailed ? null : <Empty />) : <div className="rp-node-group-cards">
          {visibleGroups.map(group => <Card key={group.id} className="rp-node-group-card"
            title={<Button type="text" onClick={() => setExpandedCard(expandedCard === group.id ? null : group.id)} aria-expanded={expandedCard === group.id}><Typography.Text strong>{group.name}</Typography.Text><Tag style={{ marginLeft: 12 }}>{typeLabel(group.group_type)}</Tag></Button>}
            extra={columns.find(column => column.key === 'action')?.render?.(undefined as never, group)}>
            <div className="rp-node-group-meta">
              {columns.filter(column => !['name', 'group_type', 'id', 'action'].includes(column.key)).map(column => <div key={column.key}><Typography.Text type="secondary">{column.title}</Typography.Text><span>{column.render ? column.render(group[column.dataIndex as keyof DeviceGroup] as never, group) : String(group[column.dataIndex as keyof DeviceGroup] ?? '-')}</span></div>)}
            </div>
            {expandedCard === group.id ? expandedRowRender(group) : null}
          </Card>)}
        </div>}
      </> : (
      <Table
        dataSource={groups}
        columns={columns}
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 20 }}
        expandable={{
          expandedRowRender,
          rowExpandable: () => true,
        }}
      />
      )}
      <NodeDiagnosisDrawer target={diagnosis} onClose={() => setDiagnosis(null)} t={t} />
      <Drawer title={t('nodeInspect')} open={!!inspecting} onClose={() => setInspecting(null)} size="90%" destroyOnHidden>
        {inspecting && <NodeStatusPage flat poolNodes={isAdmin ? poolNodes : []} focusIdentity={inspecting} />}
      </Drawer>

      <Modal title={t('addGroup')} open={createOpen} onCancel={() => setCreateOpen(false)} onOk={() => createForm.submit()} okText={t('create')} cancelText={t('cancel')}>
        <Form form={createForm} onFinish={handleCreate} layout="vertical">
          <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input placeholder="tokyo-node-1" /></Form.Item>
          {isAdmin && (
            <Form.Item name="owner_uid" label={t('owner')} extra={t('ownerHint')}>
              <Select allowClear placeholder={t('ownerSelf')} options={users.map(u => ({ value: u.id, label: u.username }))} />
            </Form.Item>
          )}
          {/* v1.0.4: new groups cannot be type 'out' (egress). */}
          <Form.Item name="group_type" label={t('type')} rules={[{ required: true }]} initialValue="in">
            <Select options={groupTypeOptions} />
          </Form.Item>
          {createIsMonitor ? (
            <Alert
              type="info"
              showIcon
              title={t('monitorOnlyNoForwardTitle')}
              description={t('monitorOnlyNoForwardDesc')}
            />
          ) : (
            <>
              {createType === 'out' ? <Form.Item name="connect_host" label={t('connectHost')} rules={[{ required: true }]}><Input placeholder="1.2.3.4 or node.example.com" /></Form.Item> : null}
              <Form.Item name="port_range" label={t('portRange')} rules={[{ required: true }]} initialValue="10000-65535"><Input placeholder="10000-65535" /></Form.Item>
              {/* v1.0.8: billing rate. Users are charged real bytes × rate; the
                  rule/user byte counters keep real bytes. 1.0 = bill as used. */}
              <Form.Item name="rate" label={t('rate')} initialValue={1.0} extra={t('rateHint')} rules={[{ required: true }]}>
                <InputNumber min={0.1} max={100} step={0.1} style={{ width: '100%' }} />
              </Form.Item>
              {/* v1.0.7: hide this group from regular users' node-status / available
                  lines. Admins always see it. */}
              <Form.Item name="hidden" label={t('groupHidden')} valuePropName="checked" initialValue={false} extra={t('groupHiddenHint')}>
                <Switch />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>

      <Modal title={t('editGroup')} open={editOpen} onCancel={() => setEditOpen(false)} onOk={() => editForm.submit()} okText={t('save')} cancelText={t('cancel')}>
        <Form form={editForm} onFinish={handleUpdate} layout="vertical">
          <Form.Item name="name" label={t('name')}><Input /></Form.Item>
          <Form.Item name="group_type" label={t('type')}><Select options={groupTypeOptions} /></Form.Item>
          {editIsMonitor ? (
            <Alert
              type="info"
              showIcon
              title={t('monitorOnlyNoForwardTitle')}
              description={`${t('monitorOnlyNoForwardDesc')} ${t('monitorOnlyEditKeepsFields')}`}
            />
          ) : (
            <>
              {editType === 'out' ? <Form.Item name="connect_host" label={t('connectHost')}><Input /></Form.Item> : null}
              <Form.Item name="port_range" label={t('portRange')}><Input /></Form.Item>
              <Form.Item name="rate" label={t('rate')} extra={t('rateHint')}>
                <InputNumber min={0.1} max={100} step={0.1} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="hidden" label={t('groupHidden')} valuePropName="checked" extra={t('groupHiddenHint')}>
                <Switch />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>

      {/* v1.2.3: rotate confirmation. Deliberately heavier than a Popconfirm —
          this disconnects every node in the group until each one is manually
          re-enrolled, so it states the node count and requires the group name
          to be typed. */}
      <Modal
        title={t('rotateTokenConfirmTitle')}
        open={!!rotating}
        onCancel={() => { setRotating(null); setConfirmName(''); }}
        onOk={handleRotateToken}
        okText={t('rotateTokenConfirmOk')}
        cancelText={t('cancel')}
        confirmLoading={rotateBusy}
        okButtonProps={{ danger: true, disabled: confirmName.trim() !== (rotating?.name ?? '') }}
      >
        {rotating && (
          <>
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              title={t('rotateTokenWarnTitle').replace('{count}', String(nodeCount(rotating.id)))}
              description={t('rotateTokenWarnDesc')}
            />
            <div style={{ marginBottom: 6 }}>
              {t('rotateTokenTypeName').replace('{name}', rotating.name)}
            </div>
            <Input
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              placeholder={rotating.name}
              autoComplete="off"
            />
          </>
        )}
      </Modal>
    </>
  );
}
