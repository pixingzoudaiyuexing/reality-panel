import { Alert, Button, Empty, Select, Space, Spin, Tag, Typography, message } from 'antd';
import { SaveOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../../api/client';
import type { ApiEnvelope, CarrierAffinityView, CarrierLineBinding, CarrierLineCatalog, RelayDnsRecordView, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';
import { carrierApplyErrorMessage } from './carrierErrors';
import {
  assignCarrierLines,
  buildCarrierLineOptions,
  carrierLineMatchesSearch,
  isCarrierMutableLineId,
  mutableCarrierBindings,
} from './carrierCatalog';

const { Text } = Typography;

interface Props {
  groupId: number;
  nodes: RelayReadyNode[];
  t: Tfn;
  dnsRecords?: RelayDnsRecordView[];
  onViewChange?: (view: CarrierAffinityView | null) => void;
  onCatalogChange?: (catalog: CarrierLineCatalog | null) => void;
  onAvailabilityChange?: (state: 'loading' | 'ready' | 'error') => void;
  activeMode?: 'normal' | 'carrier' | 'schedule' | 'failover';
}

function normalize(defaultNodeId: string | null | undefined, bindings: CarrierLineBinding[]): string {
  return JSON.stringify({ default_node_id: defaultNodeId ?? null, bindings: [...bindings]
    .map((binding) => ({ line_id: binding.line_id, mode: binding.mode, node_id: binding.node_id ?? null }))
    .sort((left, right) => left.line_id < right.line_id ? -1 : left.line_id > right.line_id ? 1 : 0) });
}

function transactionLabel(view: CarrierAffinityView, t: Tfn) {
  switch (view.transaction.state) {
    case 'switching': return { color: 'processing', label: t('carrierStateApplying') } as const;
    case 'rolling_back': return { color: 'warning', label: t('carrierStateRollingBack') } as const;
    case 'failed_manual_intervention': return { color: 'error', label: t('carrierStateSplit') } as const;
    case 'failed':
    case 'failed_rolled_back': return { color: 'error', label: t('carrierStateFailed') } as const;
    default: return { color: 'success', label: t('carrierStateEffective') } as const;
  }
}

function nodeLines(bindings: CarrierLineBinding[], nodeId: string, defaultNodeId?: string | null): string[] {
  return bindings
    .filter((binding) => isCarrierMutableLineId(binding.line_id))
    .filter((binding) => binding.mode === 'node' ? binding.node_id === nodeId : defaultNodeId === nodeId)
    .map((binding) => binding.line_id)
    .sort((left, right) => left.localeCompare(right));
}

export function CarrierAffinityPanel({ groupId, nodes, t, onViewChange, onCatalogChange, onAvailabilityChange, activeMode = 'normal' }: Props) {
  const [view, setView] = useState<CarrierAffinityView | null>(null);
  const [catalog, setCatalog] = useState<CarrierLineCatalog | null>(null);
  const [draft, setDraft] = useState<CarrierLineBinding[]>([]);
  const [draftDefaultNodeId, setDraftDefaultNodeId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [affinity, lines] = await Promise.all([
        api.get<unknown, ApiEnvelope<CarrierAffinityView>>(`/groups/${groupId}/carrier-affinity`),
        api.get<unknown, ApiEnvelope<CarrierLineCatalog>>(`/groups/${groupId}/carrier-lines`),
      ]);
      if (affinity.code !== 0 || !affinity.data || lines.code !== 0 || !lines.data) throw new Error(affinity.message || lines.message);
      setView(affinity.data);
      setCatalog(lines.data);
      setDraft(mutableCarrierBindings(affinity.data.pending_policy?.bindings ?? affinity.data.active_policy.bindings));
      setDraftDefaultNodeId(
        affinity.data.pending_policy?.default_node_id
          ?? affinity.data.active_policy.default_node_id
          ?? affinity.data.default_node_id,
      );
      setLoadError(false);
      onViewChange?.(affinity.data);
      onCatalogChange?.(lines.data);
      onAvailabilityChange?.('ready');
    } catch {
      setLoadError(true);
      onAvailabilityChange?.('error');
    } finally {
      setLoading(false);
    }
  }, [groupId, onAvailabilityChange, onCatalogChange, onViewChange]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (view?.transaction.state !== 'switching' && view?.transaction.state !== 'rolling_back') return;
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load, view?.transaction.state]);

  const activePolicy = view?.active_policy;
  const dirty = normalize(draftDefaultNodeId, draft)
    !== normalize(activePolicy?.default_node_id ?? view?.default_node_id, activePolicy?.bindings ?? []);
  const transactionBusy = view?.transaction.state === 'switching' || view?.transaction.state === 'rolling_back';
  const mutationLocked = transactionBusy || view?.transaction.state === 'failed_manual_intervention';
  const catalogUnavailable = !catalog || catalog.stale;
  const status = view ? transactionLabel(view, t) : null;
  const effectiveDefaultNodeId = nodes.find((node) => node.preferred)?.node_id ?? view?.default_node_id;
  const hasLegacyDefaultBinding = [
    ...(view?.active_policy.bindings ?? []),
    ...(view?.pending_policy?.bindings ?? []),
  ].some((binding) => !isCarrierMutableLineId(binding.line_id));
  const names = useMemo(() => new Map((catalog?.lines ?? []).map((line) => [
    line.id,
    line.id === 'default' ? t('carrierAllNetworkDefault') : line.name || line.id,
  ])), [catalog, t]);
  const lineOptions = useMemo(() => {
    const ids = new Set((catalog?.lines ?? []).map((line) => line.id));
    draft.forEach((binding) => ids.add(binding.line_id));
    return buildCarrierLineOptions(ids, names);
  }, [catalog, draft, names]);

  const assignLines = (nodeId: string, selected: string[]) => {
    setDraft((current) => assignCarrierLines(current, nodeId, selected, draftDefaultNodeId));
  };

  const save = async () => {
    if (!dirty || mutationLocked || catalogUnavailable) return;
    setSaving(true);
    try {
      const response = await api.put<unknown, ApiEnvelope<CarrierAffinityView>>(`/groups/${groupId}/carrier-affinity`, {
        default_node_id: draftDefaultNodeId,
        bindings: mutableCarrierBindings(draft),
      });
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setView(response.data);
      setDraft(mutableCarrierBindings(response.data.pending_policy?.bindings ?? response.data.active_policy.bindings));
      setDraftDefaultNodeId(
        response.data.pending_policy?.default_node_id
          ?? response.data.active_policy.default_node_id
          ?? response.data.default_node_id,
      );
      onViewChange?.(response.data);
      message.success(t(activeMode === 'carrier' ? 'carrierSaveStarted' : 'carrierSaveInactive'));
    } catch (error) {
      message.error(carrierApplyErrorMessage(error, t));
    } finally {
      setSaving(false);
    }
  };

  if (loading && !view) return <div style={{ padding: 12, textAlign: 'center' }}><Spin size="small" /></div>;
  if (loadError && !view) return <Alert type="warning" showIcon title={t('carrierLoadFailed')} action={<Button size="small" onClick={() => void load()}>{t('refresh')}</Button>} />;

  return (
    <section data-testid="carrier-affinity-panel" className="rp-routing-section">
      <div className="rp-section-heading">
        <Space size={8} wrap>{status ? <Tag color={status.color}>{status.label}</Tag> : null}</Space>
        <Button size="small" type="primary" icon={<SaveOutlined />} loading={saving} disabled={!dirty || mutationLocked || catalogUnavailable} onClick={() => void save()}>{t('carrierSave')}</Button>
      </div>
      {transactionBusy ? <Alert type="info" showIcon title={t('carrierBusy')} style={{ margin: '10px 0' }} /> : null}
      {catalog?.stale ? <Alert type="warning" showIcon title={t('carrierCatalogStale')} style={{ margin: '10px 0' }} /> : null}
      {activeMode !== 'carrier' ? <Alert type="info" showIcon title={t('routingModeInactiveConfig')} style={{ margin: '10px 0' }} /> : null}
      {hasLegacyDefaultBinding ? <Alert type="warning" showIcon title={t('carrierLegacyDefaultBinding')} style={{ margin: '10px 0' }} /> : null}
      {view?.transaction.state === 'failed_manual_intervention' ? <Alert type="error" showIcon title={t('carrierSplitTitle')} description={t('carrierSplitDescription')} style={{ margin: '10px 0' }} /> : null}
      {nodes.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('carrierEmpty')} /> : (
        <div className="rp-carrier-node-grid" role="table" aria-label={t('carrierAffinityTitle')}>
          <div className="rp-carrier-node-grid-head" role="row"><Text>{t('nodes')}</Text><Text>IP</Text><Text>{t('carrierAllNetworkDefault')}</Text><Text>{t('carrierLine')}</Text></div>
          {nodes.map((node) => (
            <div className="rp-carrier-node-grid-row" role="row" data-testid={`carrier-node-${node.node_id}`} key={node.node_id}>
              <Text code>{node.node_id}</Text>
              <Text code>{node.public_ipv4 ?? '-'}</Text>
              <Space orientation="vertical" size={4}>
                <Space size={4}><Tag color={node.online ? 'green' : undefined}>{node.online ? t('online') : t('offline')}</Tag><Tag color={node.ready ? 'green' : 'orange'}>{node.ready ? t('relayReady') : t('relayNotReady')}</Tag></Space>
                {draftDefaultNodeId === node.node_id ? (
                  <Tag color="blue" data-testid="carrier-default-node-indicator">{t('carrierDefaultSelected')}</Tag>
                ) : (
                  <Button size="small" disabled={mutationLocked} onClick={() => setDraftDefaultNodeId(node.node_id)}>{t('carrierSetDefault')}</Button>
                )}
                {effectiveDefaultNodeId === node.node_id && activeMode !== 'carrier' ? <Text type="secondary">{t('routingEffectiveDefault')}</Text> : null}
              </Space>
              <Space orientation="vertical" size={4} style={{ width: '100%' }}>
                <Select mode="multiple" showSearch aria-label={`${node.node_id} ${t('carrierLine')}`} value={nodeLines(draft, node.node_id, draftDefaultNodeId)} disabled={mutationLocked || catalogUnavailable} placeholder={t('carrierNotConfigured')} options={lineOptions} filterOption={(query, option) => carrierLineMatchesSearch(query, { value: String(option?.value ?? ''), label: String(option?.label ?? '') })} onChange={(values) => assignLines(node.node_id, values)} style={{ width: '100%' }} />
              </Space>
            </div>
          ))}
        </div>
      )}
      <Text type="secondary" className="rp-provider-decides-note">{t('carrierUnconfiguredHint')}</Text>
    </section>
  );
}
