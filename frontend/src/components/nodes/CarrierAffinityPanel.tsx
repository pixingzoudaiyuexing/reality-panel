import { Alert, Button, Empty, Select, Space, Spin, Tag, Typography, message } from 'antd';
import { SaveOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../../api/client';
import type { ApiEnvelope, CarrierAffinityView, CarrierLineBinding, CarrierLineCatalog, RelayDnsRecordView, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';

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

function normalize(bindings: CarrierLineBinding[]): string {
  return JSON.stringify([...bindings]
    .map((binding) => ({ line_id: binding.line_id, mode: binding.mode, node_id: binding.node_id ?? null }))
    .sort((left, right) => left.line_id < right.line_id ? -1 : left.line_id > right.line_id ? 1 : 0));
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
    .filter((binding) => binding.mode === 'node' ? binding.node_id === nodeId : defaultNodeId === nodeId)
    .map((binding) => binding.line_id)
    .sort((left, right) => left.localeCompare(right));
}

export function assignCarrierLines(bindings: CarrierLineBinding[], nodeId: string, selected: string[]): CarrierLineBinding[] {
  const selectedSet = new Set(selected);
  const next = bindings.filter((binding) => binding.node_id !== nodeId && !selectedSet.has(binding.line_id));
  next.push(...selected.map((lineId) => ({ line_id: lineId, mode: 'node' as const, node_id: nodeId })));
  return next.sort((left, right) => left.line_id < right.line_id ? -1 : left.line_id > right.line_id ? 1 : 0);
}

export function CarrierAffinityPanel({ groupId, nodes, t, onViewChange, onCatalogChange, onAvailabilityChange }: Props) {
  const [view, setView] = useState<CarrierAffinityView | null>(null);
  const [catalog, setCatalog] = useState<CarrierLineCatalog | null>(null);
  const [draft, setDraft] = useState<CarrierLineBinding[]>([]);
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
      setDraft(affinity.data.pending_policy?.bindings ?? affinity.data.active_policy.bindings);
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

  const active = view?.active_policy.bindings ?? [];
  const dirty = normalize(draft) !== normalize(active);
  const transactionBusy = view?.transaction.state === 'switching' || view?.transaction.state === 'rolling_back';
  const mutationLocked = transactionBusy || view?.transaction.state === 'failed_manual_intervention';
  const catalogUnavailable = !catalog || catalog.stale;
  const status = view ? transactionLabel(view, t) : null;
  const names = useMemo(() => new Map((catalog?.lines ?? []).map((line) => [line.id, line.name || line.id])), [catalog]);
  const allLineIds = useMemo(() => {
    const ids = new Set((catalog?.lines ?? []).map((line) => line.id));
    draft.forEach((binding) => ids.add(binding.line_id));
    return [...ids].sort((left, right) => (names.get(left) ?? left).localeCompare(names.get(right) ?? right));
  }, [catalog, draft, names]);

  const assignLines = (nodeId: string, selected: string[]) => {
    setDraft((current) => assignCarrierLines(current, nodeId, selected));
  };

  const save = async () => {
    if (!dirty || mutationLocked || catalogUnavailable) return;
    setSaving(true);
    try {
      const response = await api.put<unknown, ApiEnvelope<CarrierAffinityView>>(`/groups/${groupId}/carrier-affinity`, { bindings: draft });
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setView(response.data);
      setDraft(response.data.pending_policy?.bindings ?? response.data.active_policy.bindings);
      onViewChange?.(response.data);
      message.success(t('carrierSaveStarted'));
    } catch {
      message.error(t('carrierSaveFailed'));
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
      {view?.transaction.state === 'failed_manual_intervention' ? <Alert type="error" showIcon title={t('carrierSplitTitle')} description={t('carrierSplitDescription')} style={{ margin: '10px 0' }} /> : null}
      {nodes.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('carrierEmpty')} /> : (
        <div className="rp-carrier-node-grid" role="table" aria-label={t('carrierAffinityTitle')}>
          <div className="rp-carrier-node-grid-head" role="row"><Text>{t('nodes')}</Text><Text>IP</Text><Text>{t('status')}</Text><Text>{t('carrierLine')}</Text></div>
          {nodes.map((node) => (
            <div className="rp-carrier-node-grid-row" role="row" data-testid={`carrier-node-${node.node_id}`} key={node.node_id}>
              <Text code>{node.node_id}</Text>
              <Text code>{node.public_ipv4 ?? '-'}</Text>
              <Space size={4}><Tag color={node.online ? 'green' : undefined}>{node.online ? t('online') : t('offline')}</Tag><Tag color={node.ready ? 'green' : 'orange'}>{node.ready ? t('relayReady') : t('relayNotReady')}</Tag></Space>
              <Select mode="multiple" aria-label={`${node.node_id} ${t('carrierLine')}`} value={nodeLines(draft, node.node_id, view?.default_node_id)} disabled={mutationLocked || catalogUnavailable} placeholder={t('carrierNotConfigured')} options={allLineIds.map((lineId) => ({ value: lineId, label: names.get(lineId) ?? lineId }))} onChange={(values) => assignLines(node.node_id, values)} style={{ width: '100%' }} />
            </div>
          ))}
        </div>
      )}
      <Text type="secondary" className="rp-provider-decides-note">{t('carrierUnconfiguredHint')}</Text>
    </section>
  );
}
