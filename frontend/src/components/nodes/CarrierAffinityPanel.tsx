import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Empty,
  Modal,
  Popconfirm,
  Select,
  Space,
  Spin,
  Tag,
  TreeSelect,
  Typography,
  message,
} from 'antd';
import { DeleteOutlined, PlusOutlined, SaveOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type {
  ApiEnvelope,
  CarrierAffinityView,
  CarrierLineBinding,
  CarrierLineCatalog,
  CarrierLineMode,
  RelayReadyNode,
} from '../../api/types';
import type { Tfn } from './types';
import { buildCarrierCatalogTree } from './carrierCatalog';

const { Text } = Typography;

interface Props {
  groupId: number;
  nodes: RelayReadyNode[];
  t: Tfn;
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

export function CarrierAffinityPanel({ groupId, nodes, t }: Props) {
  const [view, setView] = useState<CarrierAffinityView | null>(null);
  const [draft, setDraft] = useState<CarrierLineBinding[]>([]);
  const [catalog, setCatalog] = useState<CarrierLineCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState(false);
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

  return (
    <div data-testid="carrier-affinity-panel" style={{ marginTop: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
        <Space size={8} wrap>
          <Text strong>{t('carrierAffinityTitle')}</Text>
          {status ? <Tag color={status.color}>{status.label}</Tag> : null}
          {view ? (
            <Text type="secondary">
              {t('carrierDefaultRelay')}: <Text code>{view.default_node_id ?? '-'}</Text>
            </Text>
          ) : null}
        </Space>
        <Button
          size="small"
          icon={<PlusOutlined />}
          disabled={mutationLocked}
          onClick={openAdd}
        >
          {t('carrierAddLine')}
        </Button>
      </div>

      {loading && !view ? <div style={{ padding: 12, textAlign: 'center' }}><Spin size="small" /></div> : null}
      {loadError && !view ? <Alert type="warning" showIcon title={t('carrierLoadFailed')} /> : null}
      {transactionBusy ? <Alert type="info" showIcon title={t('carrierBusy')} style={{ marginBottom: 8 }} /> : null}
      {view?.transaction.state === 'failed_manual_intervention' ? (
        <Alert type="error" showIcon title={t('carrierStateSplit')} style={{ marginBottom: 8 }} />
      ) : null}

      {view && draft.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('carrierEmpty')} />
      ) : null}
      {view && draft.length > 0 ? (
        <div>
          {draft.map((binding) => {
            const server = bindingViews.get(binding.line_id);
            const catalogAvailable = server?.catalog_available ?? catalogNames.has(binding.line_id);
            const modeLocked = mutationLocked || !catalogAvailable || Boolean(catalog?.stale);
            const effectiveNode = binding.mode === 'follow_default'
              ? view.default_node_id
              : binding.node_id ?? null;
            return (
              <div
                key={binding.line_id}
                data-testid={`carrier-binding-${binding.line_id}`}
                className="rp-carrier-binding-row"
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(180px, 1fr) minmax(150px, 190px) minmax(170px, 1fr) auto',
                  gap: 10,
                  alignItems: 'center',
                  minHeight: 54,
                  padding: '8px 0',
                  borderBottom: '1px solid var(--rp-border)',
                }}
              >
                <Space size={6} wrap>
                  <Text strong>{catalogNames.get(binding.line_id) ?? binding.line_id}</Text>
                  {!catalogAvailable ? <Tag color="warning">{t('carrierUnknownLine')}</Tag> : null}
                </Space>
                <Select
                  size="small"
                  value={binding.mode}
                  disabled={modeLocked}
                  aria-label={`${binding.line_id} ${t('carrierSelectMode')}`}
                  options={[
                    { value: 'not_configured', label: t('carrierNotConfigured') },
                    { value: 'follow_default', label: t('carrierFollowDefault') },
                    { value: 'node', label: t('carrierExplicitRelay') },
                  ]}
                  onChange={(mode: CarrierLineMode | 'not_configured') => {
                    if (mode === 'not_configured') {
                      setDraft((current) => current.filter((item) => item.line_id !== binding.line_id));
                    } else {
                      updateBinding(binding.line_id, mode);
                    }
                  }}
                />
                {binding.mode === 'node' ? (
                  <Space size={6} wrap>
                    <Select
                      size="small"
                      value={binding.node_id ?? undefined}
                      disabled={modeLocked}
                      aria-label={`${binding.line_id} ${t('carrierSelectRelay')}`}
                      placeholder={t('carrierSelectRelay')}
                      options={nodeOptions}
                      style={{ minWidth: 150 }}
                      onChange={(nodeId) => updateBinding(binding.line_id, 'node', nodeId)}
                    />
                    <Tag color={server?.relay_health === 'ready' ? 'green' : server?.relay_health === 'abnormal' ? 'orange' : undefined}>
                      {relayHealthLabel(server?.relay_health ?? null, t)}
                    </Tag>
                  </Space>
                ) : (
                  <Space size={6} wrap>
                    <Text type="secondary">{t('carrierActualRelay')}</Text>
                    <Text code>{effectiveNode ?? '-'}</Text>
                    <Tag color={server?.relay_health === 'ready' ? 'green' : server?.relay_health === 'abnormal' ? 'orange' : undefined}>
                      {relayHealthLabel(server?.relay_health ?? null, t)}
                    </Tag>
                  </Space>
                )}
                <Popconfirm
                  title={`${t('carrierNotConfigured')} · ${t('carrierProviderDecides')}`}
                  description={t('carrierRemoveLine')}
                  okText={t('delete')}
                  cancelText={t('cancel')}
                  onConfirm={() => setDraft((current) => current.filter((item) => item.line_id !== binding.line_id))}
                >
                  <Button
                    size="small"
                    type="text"
                    danger
                    icon={<DeleteOutlined />}
                    aria-label={`${t('carrierNotConfigured')}: ${binding.line_id}`}
                    disabled={mutationLocked}
                  />
                </Popconfirm>
              </div>
            );
          })}
        </div>
      ) : null}

      {view ? (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
          <Button
            size="small"
            type="primary"
            icon={<SaveOutlined />}
            loading={saving}
            disabled={!dirty || mutationLocked || (changedUpsert && catalogUnavailable)}
            onClick={() => void save()}
          >
            {t('carrierSave')}
          </Button>
        </div>
      ) : null}

      <Modal
        title={t('carrierAddLine')}
        open={addOpen}
        okText={t('add')}
        cancelText={t('cancel')}
        okButtonProps={{
          disabled: !newLineId || (newMode === 'node' && !newNodeId) || catalogUnavailable,
        }}
        onOk={addLine}
        onCancel={() => setAddOpen(false)}
      >
        <Space orientation="vertical" size={12} style={{ display: 'flex' }}>
          {catalogError ? <Alert type="warning" showIcon title={t('carrierCatalogUnavailable')} /> : null}
          {catalog?.stale ? <Alert type="warning" showIcon title={t('carrierCatalogStale')} /> : null}
          <TreeSelect
            aria-label={t('carrierSelectLine')}
            treeData={availableTree}
            value={newLineId}
            loading={catalogLoading}
            disabled={catalogLoading || catalogUnavailable}
            placeholder={t('carrierSelectLine')}
            treeDefaultExpandAll
            style={{ width: '100%' }}
            onChange={setNewLineId}
          />
          <Select
            value={newMode}
            aria-label={t('carrierSelectMode')}
            options={[
              { value: 'follow_default', label: t('carrierFollowDefault') },
              { value: 'node', label: t('carrierExplicitRelay') },
            ]}
            onChange={(mode: CarrierLineMode) => {
              setNewMode(mode);
              if (mode === 'follow_default') setNewNodeId(undefined);
            }}
          />
          {newMode === 'node' ? (
            <Select
              value={newNodeId}
              placeholder={t('carrierSelectRelay')}
              options={nodeOptions}
              onChange={setNewNodeId}
            />
          ) : (
            <Text type="secondary">{t('carrierActualRelay')}: {view?.default_node_id ?? '-'}</Text>
          )}
        </Space>
      </Modal>
    </div>
  );
}
