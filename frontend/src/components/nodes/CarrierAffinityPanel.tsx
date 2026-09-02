import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Drawer,
  Empty,
  Popconfirm,
  Select,
  Space,
  Spin,
  Tag,
  Table,
  TreeSelect,
  Typography,
  message,
} from 'antd';
import { DeleteOutlined, EditOutlined, PlusOutlined, SaveOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type {
  ApiEnvelope,
  CarrierAffinityView,
  CarrierLineBinding,
  CarrierLineCatalog,
  CarrierLineMode,
  RelayDnsRecordView,
  RelayReadyNode,
} from '../../api/types';
import type { Tfn } from './types';
import { buildCarrierCatalogTree } from './carrierCatalog';

const { Text } = Typography;

interface Props {
  groupId: number;
  nodes: RelayReadyNode[];
  t: Tfn;
  dnsRecords?: RelayDnsRecordView[];
  onViewChange?: (view: CarrierAffinityView | null) => void;
  onCatalogChange?: (catalog: CarrierLineCatalog | null) => void;
  onAvailabilityChange?: (state: 'loading' | 'ready' | 'error') => void;
}

function normalizedPolicy(bindings: CarrierLineBinding[]): string {
  return JSON.stringify(
    [...bindings]
      .map((binding) => ({
        line_id: binding.line_id,
        mode: binding.mode,
        node_id: binding.mode === 'node' ? binding.node_id ?? null : null,
      }))
      .sort((left, right) => left.line_id.localeCompare(right.line_id)),
  );
}

function transactionLabel(view: CarrierAffinityView, t: Tfn) {
  switch (view.transaction.state) {
    case 'switching':
      return { color: 'processing', label: t('carrierStateApplying') } as const;
    case 'rolling_back':
      return { color: 'warning', label: t('carrierStateRollingBack') } as const;
    case 'failed_manual_intervention':
      return { color: 'error', label: t('carrierStateSplit') } as const;
    case 'failed':
    case 'failed_rolled_back':
      return { color: 'error', label: t('carrierStateFailed') } as const;
    default:
      return { color: 'success', label: t('carrierStateEffective') } as const;
  }
}

function relayHealthLabel(health: string | null, t: Tfn): string {
  if (health === 'ready') return t('carrierRelayReady');
  if (health === 'abnormal') return t('carrierRelayAbnormal');
  if (health === 'offline') return t('carrierRelayOffline');
  return '-';
}

function dnsStateLabel(state: string, t: Tfn) {
  if (state === 'effective') return { color: 'success', label: t('carrierDnsEffective') } as const;
  if (state === 'applying') return { color: 'processing', label: t('carrierDnsApplying') } as const;
  if (state === 'pending') return { color: 'warning', label: t('carrierDnsPending') } as const;
  if (state === 'failed') return { color: 'error', label: t('carrierDnsFailed') } as const;
  return { color: 'default', label: t('carrierDnsUnknown') } as const;
}

function recordStateLabel(state: string | null, t: Tfn) {
  if (state === 'PROPAGATED') return { color: 'success', label: t('carrierRecordPropagated') } as const;
  if (['PENDING', 'SYNCING', 'MUTATION_VERIFIED', 'PROPAGATING'].includes(state ?? '')) {
    return { color: 'processing', label: t('carrierRecordApplying') } as const;
  }
  if (state === 'CONFLICT') return { color: 'warning', label: t('carrierRecordConflict') } as const;
  if (state === 'FAILED') return { color: 'error', label: t('carrierRecordFailed') } as const;
  return { color: 'default', label: t('carrierRecordUnknown') } as const;
}

export function CarrierAffinityPanel({ groupId, nodes, t, dnsRecords = [], onViewChange, onCatalogChange, onAvailabilityChange }: Props) {
  const [view, setView] = useState<CarrierAffinityView | null>(null);
  const [draft, setDraft] = useState<CarrierLineBinding[]>([]);
  const [catalog, setCatalog] = useState<CarrierLineCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [newLineId, setNewLineId] = useState<string>();
  const [newMode, setNewMode] = useState<CarrierLineMode>('follow_default');
  const [newNodeId, setNewNodeId] = useState<string>();

  const fetchAffinity = useCallback(async () => {
    const response = await api.get<unknown, ApiEnvelope<CarrierAffinityView>>(
      `/groups/${groupId}/carrier-affinity`,
    );
    if (response.code !== 0 || !response.data) throw new Error(response.message);
    return response.data;
  }, [groupId]);

  const fetchCatalog = useCallback(async () => {
    const response = await api.get<unknown, ApiEnvelope<CarrierLineCatalog>>(
      `/groups/${groupId}/carrier-lines`,
    );
    if (response.code !== 0 || !response.data) throw new Error(response.message);
    return response.data;
  }, [groupId]);

  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    try {
      const next = await fetchAffinity();
      setView(next);
      setDraft((next.pending_policy ?? next.active_policy).bindings);
      setLoadError(false);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [fetchAffinity]);

  const loadCatalog = useCallback(async () => {
    setCatalogLoading(true);
    try {
      setCatalog(await fetchCatalog());
      setCatalogError(false);
    } catch {
      setCatalogError(true);
    } finally {
      setCatalogLoading(false);
    }
  }, [fetchCatalog]);

  useEffect(() => {
    void load(true);
    void loadCatalog();
  }, [load, loadCatalog]);

  useEffect(() => onViewChange?.(view), [onViewChange, view]);
  useEffect(() => onCatalogChange?.(catalog), [catalog, onCatalogChange]);
  useEffect(() => {
    onAvailabilityChange?.(loading ? 'loading' : loadError ? 'error' : 'ready');
  }, [loadError, loading, onAvailabilityChange, view]);

  useEffect(() => {
    if (view?.transaction.state !== 'switching' && view?.transaction.state !== 'rolling_back') return;
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load, view?.transaction.state]);

  const activeBindings = useMemo(() => view?.active_policy.bindings ?? [], [view]);
  const dirty = normalizedPolicy(draft) !== normalizedPolicy(activeBindings);
  const activeByLine = useMemo(
    () => new Map(activeBindings.map((binding) => [binding.line_id, binding])),
    [activeBindings],
  );
  const changedUpsert = draft.some((binding) => {
    const active = activeByLine.get(binding.line_id);
    return !active || normalizedPolicy([active]) !== normalizedPolicy([binding]);
  });
  const transactionBusy = view?.transaction.state === 'switching' || view?.transaction.state === 'rolling_back';
  const mutationLocked = transactionBusy || view?.transaction.state === 'failed_manual_intervention';
  const catalogUnavailable = view?.catalog_stale || catalog?.stale || catalogError;
  const status = view ? transactionLabel(view, t) : null;
  const catalogNames = useMemo(
    () => new Map((catalog?.lines ?? []).map((line) => [line.id, line.name || line.id])),
    [catalog],
  );
  const bindingViews = useMemo(
    () => new Map((view?.bindings ?? []).map((binding) => [binding.line_id, binding])),
    [view],
  );
  const availableTree = useMemo(
    () => buildCarrierCatalogTree(
      (catalog?.lines ?? []).filter((line) => !draft.some((binding) => binding.line_id === line.id)),
    ),
    [catalog, draft],
  );
  const nodeOptions = nodes.map((node) => ({
    value: node.node_id,
    label: node.public_ipv4 ?? node.node_id,
    disabled: !node.ready,
  }));

  const updateBinding = (lineId: string, mode: CarrierLineMode, nodeId?: string) => {
    setDraft((current) => current.map((binding) => (
      binding.line_id === lineId
        ? { line_id: lineId, mode, node_id: mode === 'node' ? nodeId ?? null : null }
        : binding
    )));
  };

  const save = async () => {
    if (!dirty || mutationLocked || (changedUpsert && catalogUnavailable)) return;
    setSaving(true);
    try {
      const response = await api.put<unknown, ApiEnvelope<CarrierAffinityView>>(
        `/groups/${groupId}/carrier-affinity`,
        { bindings: draft },
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setView(response.data);
      setDraft((response.data.pending_policy ?? response.data.active_policy).bindings);
      message.success(t('carrierSaveStarted'));
      setEditOpen(false);
    } catch {
      message.error(t('carrierSaveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const openAdd = () => {
    setNewLineId(undefined);
    setNewMode('follow_default');
    setNewNodeId(undefined);
    setAddOpen(true);
    void loadCatalog();
  };

  const openEdit = () => {
    setDraft((view?.pending_policy ?? view?.active_policy ?? { bindings: [] }).bindings);
    setAddOpen(false);
    setEditOpen(true);
  };

  const addLine = () => {
    if (!newLineId || (newMode === 'node' && !newNodeId) || catalogUnavailable) return;
    setDraft((current) => [
      ...current,
      {
        line_id: newLineId,
        mode: newMode,
        node_id: newMode === 'node' ? newNodeId ?? null : null,
      },
    ]);
    setAddOpen(false);
  };

  const nodeById = new Map(nodes.map((node) => [node.node_id, node]));
  const nodeByIp = new Map(nodes.flatMap((node) => node.public_ipv4 ? [[node.public_ipv4, node] as const] : []));
  const nodeLabel = (nodeId?: string | null) => nodeId ? nodeById.get(nodeId)?.public_ipv4 ?? nodeId : '-';
  const valueLabel = (value?: string | null) => value ? nodeByIp.get(value)?.public_ipv4 ?? value : '-';
  const splitGroups = Array.from(dnsRecords.reduce((groups, record) => {
    const records = groups.get(record.line_key) ?? [];
    records.push(record);
    groups.set(record.line_key, records);
    return groups;
  }, new Map<string, RelayDnsRecordView[]>()).entries());

  return (
    <section data-testid="carrier-affinity-panel" className="rp-routing-section">
      <div className="rp-section-heading">
        <Space size={8} wrap>{status ? <Tag color={status.color}>{status.label}</Tag> : null}</Space>
        <Button size="small" icon={<EditOutlined />} disabled={!view || mutationLocked} onClick={openEdit}>
          {t('carrierEditPolicy')}
        </Button>
      </div>

      {loading && !view ? <div style={{ padding: 12, textAlign: 'center' }}><Spin size="small" /></div> : null}
      {loadError && !view ? <Alert type="warning" showIcon title={t('carrierLoadFailed')} /> : null}
      {transactionBusy ? <Alert type="info" showIcon title={t('carrierBusy')} style={{ marginBottom: 8 }} /> : null}
      {view?.transaction.state === 'failed_manual_intervention' ? (
        <Alert
          type="error"
          showIcon
          title={t('carrierSplitTitle')}
          description={t('carrierSplitDescription')}
          style={{ marginBottom: 10 }}
        />
      ) : view?.transaction.state.startsWith('failed') ? (
        <Alert
          type="error"
          showIcon
          title={t('carrierStateFailed')}
          description={[view.transaction.last_error, view.transaction.rollback_error].filter(Boolean).join(' · ') || undefined}
          style={{ marginBottom: 10 }}
        />
      ) : null}

      {view && view.bindings.length > 0 ? (
        <div className="rp-routing-grid" role="table" aria-label={t('carrierAffinityTitle')}>
          <div className="rp-routing-grid-head" role="row">
            <Text>{t('carrierLine')}</Text><Text>{t('carrierPolicy')}</Text><Text>{t('carrierTargetRelay')}</Text><Text>{t('carrierDnsStatus')}</Text>
          </div>
          {view.bindings.map((binding) => {
            const state = dnsStateLabel(binding.dns_state, t);
            const target = nodeLabel(binding.effective_node_id);
            return (
              <div className="rp-routing-grid-row" role="row" data-testid={`carrier-route-${binding.line_id}`} key={binding.line_id}>
                <Space size={6} wrap>
                  <Text strong>{catalogNames.get(binding.line_id) ?? binding.line_id}</Text>
                  {!binding.catalog_available ? <Tag color="warning">{t('carrierUnknownLine')}</Tag> : null}
                </Space>
                <Text>{binding.mode === 'follow_default' ? `${t('carrierFollowDefault')} → ${target}` : `${t('carrierExplicitRelay')} → ${target}`}</Text>
                <Text code>{target}</Text>
                <Tag color={state.color}>{state.label}</Tag>
              </div>
            );
          })}
        </div>
      ) : null}
      {view && view.bindings.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('carrierEmpty')} /> : null}
      {view ? <Text type="secondary" className="rp-provider-decides-note">{t('carrierUnconfiguredHint')}</Text> : null}

      {view?.transaction.state === 'failed_manual_intervention' && splitGroups.length > 0 ? (
        <div className="rp-carrier-split-details" data-testid="carrier-split-details">
          {splitGroups.map(([lineKey, records]) => {
            const atTarget = records.filter((record) => record.position === 'target').length;
            const atRollback = records.filter((record) => record.position === 'rollback').length;
            const unknown = records.length - atTarget - atRollback;
            const lineId = records[0]?.line_id ?? lineKey;
            return (
              <div className="rp-carrier-split-line" key={lineKey}>
                <Space size={6} wrap>
                  <Text strong>{lineKey === 'default' ? t('relayPreferenceDefaultLine') : catalogNames.get(lineId) ?? lineId}</Text>
                  <Tag color="green">{t('carrierAtTarget').replace('{count}', String(atTarget))}</Tag>
                  <Tag color="orange">{t('carrierAtRollback').replace('{count}', String(atRollback))}</Tag>
                  <Tag>{t('carrierAtUnknown').replace('{count}', String(unknown))}</Tag>
                  <Text type="secondary">{t('carrierTargetRelay')}: {valueLabel(records[0]?.target_value)}</Text>
                </Space>
                <Table<RelayDnsRecordView>
                  size="small"
                  pagination={false}
                  rowKey={(record) => `${record.rule_id}:${record.line_key}`}
                  dataSource={records}
                  scroll={{ x: 680 }}
                  columns={[
                    { title: t('carrierRule'), dataIndex: 'rule_id', key: 'rule_id', width: 72, render: (id: number) => `#${id}` },
                    { title: 'FQDN', dataIndex: 'fqdn', key: 'fqdn', width: 180, render: (fqdn: string) => <Text code>{fqdn}</Text> },
                    { title: t('carrierExpectedValue'), dataIndex: 'expected_value', key: 'expected', width: 140, render: (value: string | null) => <Text code>{valueLabel(value)}</Text> },
                    { title: t('carrierPosition'), dataIndex: 'position', key: 'position', width: 110, render: (position: RelayDnsRecordView['position']) => t(position === 'target' ? 'carrierPositionTarget' : position === 'rollback' ? 'carrierPositionRollback' : 'carrierPositionUnknown') },
                    { title: t('carrierDnsStatus'), dataIndex: 'sync_state', key: 'state', width: 100, render: (stateValue: string | null) => { const display = recordStateLabel(stateValue, t); return <Tag color={display.color}>{display.label}</Tag>; } },
                    { title: t('carrierReason'), dataIndex: 'last_error', key: 'error', render: (error: string | null) => error ? <Text type="danger">{error}</Text> : '-' },
                  ]}
                />
              </div>
            );
          })}
        </div>
      ) : null}

      <Drawer
        title={t('carrierEditPolicy')}
        open={editOpen}
        onClose={() => { setEditOpen(false); setAddOpen(false); }}
        size="min(720px, 100vw)"
        className="rp-carrier-editor-drawer"
        footer={(
          <div className="rp-drawer-footer">
            <Button onClick={() => { setEditOpen(false); setAddOpen(false); }}>{t('cancel')}</Button>
            <Button type="primary" icon={<SaveOutlined />} loading={saving} disabled={!dirty || mutationLocked || (changedUpsert && catalogUnavailable)} onClick={() => void save()}>
              {t('carrierSave')}
            </Button>
          </div>
        )}
      >
        {catalogError ? <Alert type="warning" showIcon title={t('carrierCatalogUnavailable')} style={{ marginBottom: 10 }} /> : null}
        {catalog?.stale ? <Alert type="warning" showIcon title={t('carrierCatalogStale')} style={{ marginBottom: 10 }} /> : null}
        <div className="rp-carrier-editor-toolbar">
          <Text type="secondary">{t('carrierEditorHint')}</Text>
          <Button size="small" icon={<PlusOutlined />} disabled={mutationLocked} onClick={openAdd}>{t('carrierAddLine')}</Button>
        </div>
        {addOpen ? (
          <div className="rp-carrier-add-row">
            <TreeSelect aria-label={t('carrierSelectLine')} treeData={availableTree} value={newLineId} loading={catalogLoading} disabled={catalogLoading || catalogUnavailable} placeholder={t('carrierSelectLine')} treeDefaultExpandAll style={{ width: '100%' }} onChange={setNewLineId} />
            <Select value={newMode} aria-label={t('carrierSelectMode')} options={[{ value: 'follow_default', label: t('carrierFollowDefault') }, { value: 'node', label: t('carrierExplicitRelay') }]} onChange={(mode: CarrierLineMode) => { setNewMode(mode); if (mode === 'follow_default') setNewNodeId(undefined); }} />
            {newMode === 'node' ? <Select value={newNodeId} placeholder={t('carrierSelectRelay')} options={nodeOptions} onChange={setNewNodeId} /> : <Text type="secondary">{t('carrierTargetRelay')}: {nodeLabel(view?.default_node_id)}</Text>}
            <Space><Button onClick={() => setAddOpen(false)}>{t('cancel')}</Button><Button type="primary" disabled={!newLineId || (newMode === 'node' && !newNodeId) || catalogUnavailable} onClick={addLine}>{t('add')}</Button></Space>
          </div>
        ) : null}

        {draft.length === 0 && !addOpen ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('carrierEmpty')} />
        ) : null}

        {draft.map((binding) => {
          const server = bindingViews.get(binding.line_id);
          const catalogAvailable = server?.catalog_available ?? catalogNames.has(binding.line_id);
          const modeLocked = mutationLocked || !catalogAvailable || Boolean(catalog?.stale);
          return (
            <div key={binding.line_id} data-testid={`carrier-binding-${binding.line_id}`} className="rp-carrier-binding-row">
              <Space size={6} wrap><Text strong>{catalogNames.get(binding.line_id) ?? binding.line_id}</Text>{!catalogAvailable ? <Tag color="warning">{t('carrierUnknownLine')}</Tag> : null}</Space>
              <Select size="small" value={binding.mode} disabled={modeLocked} aria-label={`${binding.line_id} ${t('carrierSelectMode')}`} options={[{ value: 'not_configured', label: t('carrierNotConfigured') }, { value: 'follow_default', label: t('carrierFollowDefault') }, { value: 'node', label: t('carrierExplicitRelay') }]} onChange={(mode: CarrierLineMode | 'not_configured') => { if (mode === 'not_configured') setDraft((current) => current.filter((item) => item.line_id !== binding.line_id)); else updateBinding(binding.line_id, mode); }} />
              {binding.mode === 'node' ? (
                <Space size={6} wrap><Select size="small" value={binding.node_id ?? undefined} disabled={modeLocked} aria-label={`${binding.line_id} ${t('carrierSelectRelay')}`} placeholder={t('carrierSelectRelay')} options={nodeOptions} style={{ minWidth: 150 }} onChange={(nodeId) => updateBinding(binding.line_id, 'node', nodeId)} /><Tag color={server?.relay_health === 'ready' ? 'green' : server?.relay_health === 'abnormal' ? 'orange' : undefined}>{relayHealthLabel(server?.relay_health ?? null, t)}</Tag></Space>
              ) : <Text type="secondary">{t('carrierTargetRelay')}: {nodeLabel(view?.default_node_id)}</Text>}
              <Popconfirm title={`${t('carrierNotConfigured')} · ${t('carrierProviderDecides')}`} description={t('carrierRemoveLine')} okText={t('delete')} cancelText={t('cancel')} onConfirm={() => setDraft((current) => current.filter((item) => item.line_id !== binding.line_id))}>
                <Button size="small" type="text" danger icon={<DeleteOutlined />} aria-label={`${t('carrierNotConfigured')}: ${binding.line_id}`} disabled={mutationLocked} />
              </Popconfirm>
            </div>
          );
        })}
      </Drawer>
    </section>
  );
}
