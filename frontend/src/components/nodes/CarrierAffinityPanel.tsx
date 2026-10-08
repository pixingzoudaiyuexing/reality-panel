import { Alert, Button, Checkbox, Empty, Select, Space, Spin, Tag, Typography } from 'antd';
import { LoadingOutlined, SaveOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import api from '../../api/client';
import type { ApiEnvelope, CarrierAffinityView, CarrierCatalogIssue, CarrierLineBinding, CarrierLineCatalog, RelayDnsRecordView, RelayReadyNode, RoutingApplyRequest, RoutingApplyResult, RoutingMode } from '../../api/types';
import type { Tfn } from './types';
import {
  assignCarrierLines,
  buildCarrierLineOptions,
  carrierLineMatchesSearch,
  isCarrierMutableLineId,
  mutableCarrierBindings,
} from './carrierCatalog';

import { carrierDefaultNodeIds, carrierBackendTerminal, carrierOperation, carrierPolicyKey } from './carrierOperation';
import type { CarrierPolicy } from '../../api/types';

const { Text } = Typography;

interface Props {
  groupId: number;
  nodes: RelayReadyNode[];
  t: Tfn;
  dnsRecords?: RelayDnsRecordView[];
  onViewChange?: (view: CarrierAffinityView | null) => void;
  onCatalogChange?: (catalog: CarrierLineCatalog | null) => void;
  onAvailabilityChange?: (state: 'loading' | 'ready' | 'error') => void;
  activeMode?: RoutingMode;
  disabled?: boolean;
  onApply: (request: RoutingApplyRequest) => Promise<RoutingApplyResult | null>;
  onDirtyChange?: (dirty: boolean) => void;
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

function nodeLines(bindings: CarrierLineBinding[], nodeId: string, defaultNodeIds: string[]): string[] {
  return bindings
    .filter((binding) => isCarrierMutableLineId(binding.line_id))
    .filter((binding) => binding.mode === 'node' ? binding.node_id === nodeId : defaultNodeIds.includes(nodeId))
    .map((binding) => binding.line_id)
    .sort((left, right) => left.localeCompare(right));
}

function CarrierCatalogIssueAlert({ issue, t }: { issue: CarrierCatalogIssue; t: Tfn }) {
  if (issue.kind === 'no_eligible_rules') {
    return <Alert type="warning" showIcon title={t('carrierNoEligibleRules')} style={{ margin: '10px 0' }} />;
  }
  const actionableRule = issue.actionable?.level === 'rule' ? issue.actionable.rule_id : null;
  const actionableZone = issue.actionable?.level === 'zone' ? issue.actionable.domain_id : null;
  return (
    <Alert
      type="error"
      showIcon
      title={t('carrierCatalogIncompatible')}
      description={(
        <Space orientation="vertical" size={4}>
          <Text>{issue.actionable ? t('carrierCatalogActionable') : t('carrierCatalogAmbiguous')}</Text>
          {issue.zones.map((zone) => (
            <div key={zone.domain_id} data-testid={`carrier-issue-zone-${zone.domain_id}`}>
              <Text strong={actionableZone === zone.domain_id}>{zone.zone}</Text>
              <Text type="secondary"> {zone.provider_type ?? '-'} · {zone.line_count} {t('carrierCatalogLineCount')}</Text>
              {zone.rules.map((rule) => (
                <div key={rule.rule_id} style={{ marginLeft: 12 }}>
                  <Text strong={actionableRule === rule.rule_id}>Rule {rule.rule_id} · {rule.name}</Text>
                  <Text code style={{ marginLeft: 8, overflowWrap: 'anywhere' }}>{rule.sni}</Text>
                </div>
              ))}
            </div>
          ))}
        </Space>
      )}
      style={{ margin: '10px 0' }}
    />
  );
}

export function CarrierAffinityPanel({ groupId, nodes, t, onViewChange, onCatalogChange, onAvailabilityChange, activeMode = 'normal', disabled = false, onApply, onDirtyChange }: Props) {
  const [view, setView] = useState<CarrierAffinityView | null>(null);
  const [catalog, setCatalog] = useState<CarrierLineCatalog | null>(null);
  const [draft, setDraft] = useState<CarrierLineBinding[]>([]);
  const [draftDefaultNodeId, setDraftDefaultNodeId] = useState<string | null>(null);
  const [draftDefaultNodeIds, setDraftDefaultNodeIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const requestInFlight = useRef(false);
  const readInFlight = useRef(false);
  const mutationGeneration = useRef(0);
  const [mutationVersion, setMutationVersion] = useState(0);
  const [viewGeneration, setViewGeneration] = useState(-1);
  const operationKey = `reality-carrier-operation:${groupId}`;
  const [intent, setIntent] = useState<{ desired: CarrierPolicy | null; unknown: boolean; error: string | null; baseline?: string; observed?: boolean; pending?: boolean; baselineMode?: RoutingMode }>(() => {
    try {
      const stored = JSON.parse(sessionStorage.getItem(operationKey) ?? 'null');
      if (!stored) return { desired: null, unknown: false, error: null };
      let baseline = stored.baseline;
      // Pending operations saved by v1.4.7 retain their lost-response guard.
      if (typeof baseline === 'string') {
        try { const policy = JSON.parse(baseline); if (Array.isArray(policy.bindings)) baseline = carrierPolicyKey(policy); } catch { /* Keep unknown evidence protected. */ }
      }
      return { ...stored, baseline, unknown: stored.unknown || stored.pending === true, pending: false };
    }
    catch { return { desired: null, unknown: false, error: null }; }
  });
  useEffect(() => { sessionStorage.setItem(operationKey, JSON.stringify(intent)); }, [intent, operationKey]);
  const backendPhase = carrierOperation(view, intent.desired, saving, intent.unknown);
  const unchangedUnknown = intent.unknown && !intent.observed && intent.desired && intent.baseline === carrierPolicyKey(intent.desired) && (!intent.baselineMode || intent.baselineMode === activeMode);
  const phase = intent.error && !saving && !['rolling_back', 'rolled_back', 'rollback_failed'].includes(backendPhase)
    ? 'failed' : unchangedUnknown && backendPhase === 'ready' ? 'unknown' : activeMode !== 'carrier' && !intent.desired && backendPhase === 'pending' ? 'idle' : backendPhase;
  useEffect(() => {
    if (viewGeneration === mutationGeneration.current && !loadError && intent.desired && !intent.observed && (view?.pending_policy || ['switching', 'rolling_back'].includes(view?.transaction.state ?? ''))) {
      setIntent((current) => ({ ...current, observed: true }));
    }
  }, [intent.desired, intent.observed, loadError, viewGeneration, view?.pending_policy, view?.transaction.state]);
  const polling = saving || (!!intent.desired && viewGeneration !== mutationVersion) || ['syncing', 'rolling_back', 'pending', 'unknown'].includes(phase);
  const operationText = { submitting: 'carrierOperationSubmitting', unknown: 'carrierOperationUnknown', syncing: 'carrierOperationSyncing', pending: 'carrierOperationPending', ready: 'carrierOperationReady', failed: 'carrierOperationFailed', rolled_back: 'carrierOperationRolledBack', rollback_failed: 'carrierOperationRollbackFailed', rolling_back: 'carrierOperationRollingBack' } as const;


  const load = useCallback(async function loadCarrier() {
    if (readInFlight.current) return;
    readInFlight.current = true;
    const generation = mutationGeneration.current;
    setLoading(true);
    try {
      const [affinityResult, linesResult] = await Promise.allSettled([
        api.get<unknown, ApiEnvelope<CarrierAffinityView>>(`/groups/${groupId}/carrier-affinity`),
        api.get<unknown, ApiEnvelope<CarrierLineCatalog>>(`/groups/${groupId}/carrier-lines`),
      ]);
      const affinity = affinityResult.status === 'fulfilled' ? affinityResult.value : null;
      const lines = linesResult.status === 'fulfilled' ? linesResult.value : null;
      // A GET started before a new POST cannot resolve that POST's intent.
      if (generation !== mutationGeneration.current) return;
      if (!affinity || affinity.code !== 0 || !affinity.data) throw new Error('Carrier state unavailable');
      setView(affinity.data);
      setViewGeneration(generation);
      setDraft(mutableCarrierBindings(affinity.data.pending_policy?.bindings ?? affinity.data.active_policy.bindings));
      const policy = affinity.data.pending_policy ?? affinity.data.active_policy;
      const ids = carrierDefaultNodeIds(policy, affinity.data.default_node_id);
      setDraftDefaultNodeIds(ids);
      setDraftDefaultNodeId(policy.default_node_id && ids.includes(policy.default_node_id) ? policy.default_node_id : ids[0] ?? null);
      onViewChange?.(affinity.data);
      if (lines?.code === 0 && lines.data) {
        setCatalog(lines.data);
        setLoadError(false);
        onCatalogChange?.(lines.data);
        onAvailabilityChange?.('ready');
      } else {
        // Provider catalog failure must never hide the local transaction error.
        setCatalog((current) => current ? { ...current, stale: true } : null);
        setLoadError(true);
        onAvailabilityChange?.('error');
      }
    } catch {
      if (generation !== mutationGeneration.current) return;
      setViewGeneration(-1);
      setLoadError(true);
      onAvailabilityChange?.('error');
    } finally {
      readInFlight.current = false;
      setLoading(false);
      if (generation !== mutationGeneration.current) void loadCarrier();
    }
  }, [groupId, onAvailabilityChange, onCatalogChange, onViewChange]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!polling) return;
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load, polling]);

  useEffect(() => {
    if (!intent.desired || intent.pending || intent.error || saving || requestInFlight.current
      || loadError || viewGeneration !== mutationGeneration.current || !carrierBackendTerminal(view)) return;
    const policyChanged = intent.baseline !== undefined && !!view && carrierPolicyKey(view.active_policy) === carrierPolicyKey(intent.desired)
      && (intent.baseline !== carrierPolicyKey(view.active_policy) || (intent.baselineMode && intent.baselineMode !== activeMode));
    // A lost response with no server takeover remains protected. Once observed,
    // terminal server state wins even if another operation changed the policy.
    if (intent.observed || !intent.unknown || policyChanged) {
      setIntent({ desired: null, unknown: false, error: null });
    }
  }, [activeMode, intent, loadError, saving, view, viewGeneration]);

  const savedPolicy = view?.pending_policy ?? view?.active_policy;
  const dirty = carrierPolicyKey({ default_node_ids: draftDefaultNodeIds, bindings: draft })
    !== carrierPolicyKey({ default_node_ids: carrierDefaultNodeIds(savedPolicy, view?.default_node_id), bindings: savedPolicy?.bindings ?? [] });
  const transactionBusy = view?.transaction.state === 'switching' || view?.transaction.state === 'rolling_back';
  const mutationLocked = polling || transactionBusy || backendPhase === 'rollback_failed' || backendPhase === 'failed';
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
  const lineSelections = useMemo(() => {
    const selections = new Map<string, string[]>();
    for (const binding of draft) {
      const ids = binding.mode === 'node' ? (binding.node_id ? [binding.node_id] : []) : draftDefaultNodeIds;
      if (isCarrierMutableLineId(binding.line_id)) {
        selections.set(binding.line_id, [...new Set([...(selections.get(binding.line_id) ?? []), ...ids])]);
      }
    }
    return [...selections.entries()];
  }, [draft, draftDefaultNodeIds]);

  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  const assignLines = (nodeId: string, selected: string[]) => {
    setDraft((current) => assignCarrierLines(current, nodeId, selected, draftDefaultNodeIds));
  };

  const save = async () => {
    if (requestInFlight.current || (activeMode === 'carrier' && !dirty) || mutationLocked || catalogUnavailable || disabled) return;
    requestInFlight.current = true;
    mutationGeneration.current += 1;
    setMutationVersion(mutationGeneration.current);
    const submitted = { desired: { default_node_ids: draftDefaultNodeIds, default_node_id: draftDefaultNodeId, bindings: mutableCarrierBindings(draft) }, unknown: false, error: null, baseline: view ? carrierPolicyKey(view.active_policy) : undefined, observed: false, pending: true, baselineMode: activeMode };
    sessionStorage.setItem(operationKey, JSON.stringify(submitted));
    setIntent(submitted);
    setSaving(true);
    try {
      const result = await onApply({
        mode: 'carrier',
        default_node_ids: draftDefaultNodeIds,
        default_node_id: draftDefaultNodeId,
        bindings: mutableCarrierBindings(draft),
      });
      if (result === null) setIntent({ desired: null, unknown: false, error: null });
      else if (result?.client_outcome === 'failed') setIntent((current) => ({ ...current, unknown: false, error: result.client_error ?? result.business_error_code ?? 'DNS_PROVIDER_READ_FAILED' }));
      else if (result?.client_outcome === 'unknown') setIntent((current) => ({ ...current, unknown: true }));
      else if (result && !result.config_saved && result.business_error_code) setIntent((current) => ({ ...current, unknown: false, error: result.business_error_code }));
    } catch {
      setIntent((current) => ({ ...current, unknown: true }));
    } finally {
      // Reads begun while the POST was pending cannot acknowledge its outcome.
      mutationGeneration.current += 1;
      setMutationVersion(mutationGeneration.current);
      setIntent((current) => ({ ...current, pending: false }));
      requestInFlight.current = false;
      setSaving(false);
      await load();
    }
  };

  if (loading && !view) return <div style={{ padding: 12, textAlign: 'center' }}><Spin size="small" /></div>;
  if (loadError && !view) return <Alert type="warning" showIcon title={t('carrierLoadFailed')} action={<Button size="small" onClick={() => void load()}>{t('refresh')}</Button>} />;

  return (
    <section data-testid="carrier-affinity-panel" className="rp-routing-section">
      <div className="rp-section-heading">
        <Space size={8} wrap>
          {activeMode === 'carrier'
            ? status ? <Tag color={status.color}>{status.label}</Tag> : null
            : <Tag>{t('routingModeInactive')}</Tag>}
        </Space>
        <Button size="small" type="primary" icon={<SaveOutlined />} loading={saving} disabled={(activeMode === 'carrier' && !dirty) || mutationLocked || catalogUnavailable || disabled} onClick={() => void save()}>{t(activeMode === 'carrier' ? 'routingSaveChanges' : 'routingSaveAndActivate')}</Button>
      </div>
      <Text type="secondary">{t('carrierMultiNodeHint')}</Text>
      {phase !== 'idle' ? <Alert data-testid="carrier-operation" type={['failed', 'rolled_back', 'rollback_failed'].includes(phase) ? 'error' : phase === 'ready' ? 'success' : 'info'} showIcon
        icon={polling ? <LoadingOutlined /> : undefined}
        title={t(operationText[phase as keyof typeof operationText])}
        style={{ margin: '10px 0' }}
        description={<Space orientation="vertical" size={4} style={{ width: '100%' }} aria-live="polite">
          {loadError ? <Text type="warning">{t('carrierOperationReadFailed')}</Text> : null}
          {intent.error ? <Text type="danger" style={{ overflowWrap: 'anywhere' }}>{intent.error}</Text> : null}
          {view?.transaction.last_error ? <Text type="danger">{t('carrierOperationError')}: {view.transaction.last_error}</Text> : null}
          {view?.transaction.rollback_error ? <Text type="danger">{t('carrierOperationRollbackError')}: {view.transaction.rollback_error}</Text> : null}
          <Text type="secondary">{t('carrierOperationState')}: {view?.transaction.state ?? '-'} · {view?.transaction.kind ?? '-'}</Text>
          {(view?.dns_records ?? []).map((record) => <div key={`${record.rule_id}:${record.line_id}`} style={{ overflowWrap: 'anywhere' }}>
            <Text>{record.provider} · {record.line_id} · {record.fqdn} · {record.state}</Text>
            {record.last_error ? <Text type="danger"> · {record.last_error}</Text> : null}
          </div>)}
          {['failed', 'rolled_back', 'rollback_failed', 'unknown'].includes(phase) ? <Button size="small" onClick={() => void load()}>{t('carrierOperationRefresh')}</Button> : null}
        </Space>} /> : null}
      {transactionBusy ? <Alert type="info" showIcon title={t('carrierBusy')} style={{ margin: '10px 0' }} /> : null}
      {catalog?.stale ? <Alert type="warning" showIcon title={t('carrierCatalogStale')} style={{ margin: '10px 0' }} /> : null}
      {(catalog?.issues ?? []).map((issue, index) => <CarrierCatalogIssueAlert key={`${issue.kind}-${index}`} issue={issue} t={t} />)}
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
                <Checkbox
                  aria-label={`${node.node_id} ${t('carrierAllNetworkDefault')}`}
                  data-testid={draftDefaultNodeIds.includes(node.node_id) ? 'carrier-default-node-indicator' : undefined}
                  checked={draftDefaultNodeIds.includes(node.node_id)} disabled={mutationLocked || disabled}
                  onChange={(event) => {
                    const ids = event.target.checked ? [...new Set([...draftDefaultNodeIds, node.node_id])].sort() : draftDefaultNodeIds.filter((id) => id !== node.node_id);
                    setDraftDefaultNodeIds(ids);
                    setDraftDefaultNodeId(draftDefaultNodeId && ids.includes(draftDefaultNodeId) ? draftDefaultNodeId : ids[0] ?? null);
                  }}
                />
                {effectiveDefaultNodeId === node.node_id && activeMode !== 'carrier' ? <Text type="secondary">{t('routingEffectiveDefault')}</Text> : null}
              </Space>
              <Space orientation="vertical" size={4} style={{ width: '100%' }}>
                <Select mode="multiple" showSearch aria-label={`${node.node_id} ${t('carrierLine')}`} value={nodeLines(draft, node.node_id, draftDefaultNodeIds)} disabled={mutationLocked || catalogUnavailable || disabled} placeholder={t('carrierNotConfigured')} options={lineOptions} filterOption={(query, option) => carrierLineMatchesSearch(query, { value: String(option?.value ?? ''), label: String(option?.label ?? '') })} onChange={(values) => assignLines(node.node_id, values)} style={{ width: '100%' }} />
              </Space>
            </div>
          ))}
        </div>
      )}
      <Space wrap aria-label={t('carrierLineSelections')}>
        {lineSelections.map(([line, nodeIds]) => <Tag key={line} color={nodeIds.length > 1 ? 'blue' : undefined}>{names.get(line) ?? line} → {nodeIds.join(', ')}</Tag>)}
      </Space>
      <Text type="secondary" className="rp-provider-decides-note">{t('carrierUnconfiguredHint')}</Text>
    </section>
  );
}
