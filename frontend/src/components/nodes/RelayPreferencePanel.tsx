import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Divider, Modal, Space, Spin, Tabs, Tag, Tooltip, Typography, message } from 'antd';
import { MedicineBoxOutlined, ReloadOutlined, SwapOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type { ApiEnvelope, CarrierAffinityView, CarrierLineCatalog, RelayPreferenceView, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';
import { RelaySchedulePanel } from './RelaySchedulePanel';
import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { relayReadyReasonLabel } from './shared';
import { dnsSyncStateDisplay } from '../../utils/realityRuleStatus';

const { Text } = Typography;

const INITIAL_LOAD_RETRY_DELAYS_MS = [2000, 5000] as const;

type LoadPreference = (showSpinner?: boolean, allowInitialRetry?: boolean) => Promise<void>;

interface Props {
  groupId: number;
  t: Tfn;
  onDiagnoseNode?: (node: RelayReadyNode) => void;
  onViewChange?: (view: RelayPreferenceView | null) => void;
}

function switchErrorLabel(error: string | null, t: Tfn): string {
  if (!error) return t('relaySwitchUnknownError');
  const labels: Record<string, Parameters<Tfn>[0]> = {
    PUBLIC_DNS_MULTIPLE_ANSWERS: 'relaySwitchErrorMultipleAnswers',
    DNS_RECORD_CONFLICT: 'relaySwitchErrorRecordConflict',
    TARGET_STATUS_UNAVAILABLE: 'relaySwitchErrorTargetStatus',
    TARGET_PUBLIC_IPV4_UNAVAILABLE: 'relaySwitchErrorTargetIpv4',
    TARGET_PUBLIC_IPV4_CHANGED: 'relaySwitchErrorTargetIpv4Changed',
    TARGET_NOT_READY_AFTER_DNS: 'relaySwitchErrorTargetNotReady',
    DNS_SCHEDULING_FAILED: 'relaySwitchErrorScheduling',
    MUTATION_OUTCOME_UNKNOWN: 'relaySwitchErrorMutationUnknown',
    DISABLED: 'relaySwitchErrorDisabled',
    NO_ELIGIBLE_DNS_RULES: 'relaySwitchErrorNoRules',
    PENDING_NODE_MISSING: 'relaySwitchErrorPendingMissing',
    ROLLBACK_SCHEDULING_FAILED: 'relaySwitchErrorRollbackScheduling',
    ROLLBACK_RULE_NOT_ELIGIBLE: 'relaySwitchErrorRollbackRule',
    ROLLBACK_VALUE_UNAVAILABLE: 'relaySwitchErrorRollbackValue',
  };
  const key = labels[error];
  return key ? t(key) : error;
}

function requestErrorLabel(error: unknown, t: Tfn): string {
  const response = (error as { response?: { status?: number; data?: { message?: string } } }).response;
  const statusLabels: Record<number, Parameters<Tfn>[0]> = {
    404: 'relaySwitchHttpNotFound',
    409: 'relaySwitchHttpConflict',
    422: 'relaySwitchHttpUnprocessable',
    500: 'relaySwitchHttpFailed',
  };
  const friendly = t(statusLabels[response?.status ?? 0] ?? 'relaySwitchHttpFailed');
  return response?.data?.message ? `${friendly}: ${response.data.message}` : friendly;
}

function actionLabel(view: RelayPreferenceView, node: RelayReadyNode, t: Tfn): string {
  if (!node.ready) return t('relayPreferenceUnavailable');
  if (view.state === 'switching' || view.state === 'rolling_back') {
    return node.node_id === view.pending_node_id
      ? t('relayPreferenceSwitching')
      : t('relayPreferenceSwitchLocked');
  }
  if (view.state.startsWith('failed')) {
    if (node.node_id === view.pending_node_id) return t('relayPreferenceRetry');
    if (node.node_id === view.preferred_node_id) return t('relayPreferenceReconfirm');
  }
  return t('setAsDefaultLine');
}

function safeLineKey(lineKey: string): string {
  return lineKey.replace(/[^A-Za-z0-9_-]/g, '-');
}

export function RelayPreferencePanel({ groupId, t, onDiagnoseNode, onViewChange }: Props) {
  const [view, setView] = useState<RelayPreferenceView | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [submittingNodeId, setSubmittingNodeId] = useState<string | null>(null);
  const [carrierView, setCarrierView] = useState<CarrierAffinityView | null>(null);
  const [carrierCatalog, setCarrierCatalog] = useState<CarrierLineCatalog | null>(null);
  const [carrierAvailability, setCarrierAvailability] = useState<'loading' | 'ready' | 'error'>('loading');
  const operationInFlight = useRef(false);
  const viewRef = useRef<RelayPreferenceView | null>(null);
  const retryTimerRef = useRef<number | null>(null);
  const retryAttemptRef = useRef(0);
  const loadRef = useRef<LoadPreference | null>(null);

  const clearInitialLoadRetry = useCallback(() => {
    if (retryTimerRef.current !== null) {
      window.clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
    retryAttemptRef.current = 0;
  }, []);

  const fetchPreference = useCallback(async () => {
    const response = await api.get<unknown, ApiEnvelope<RelayPreferenceView>>(
      `/groups/${groupId}/relay-preference`,
    );
    if (response.code !== 0 || !response.data) throw new Error(response.message);
    return response.data;
  }, [groupId]);

  const load = useCallback(async (showSpinner = false, allowInitialRetry = false) => {
    if (operationInFlight.current) return;
    if (!allowInitialRetry) clearInitialLoadRetry();
    operationInFlight.current = true;
    if (showSpinner) setLoading(true);
    try {
      const nextView = await fetchPreference();
      viewRef.current = nextView;
      setView(nextView);
      setLoadError(false);
      clearInitialLoadRetry();
    } catch {
      setLoadError(true);
      if (allowInitialRetry && viewRef.current === null) {
        const attempt = retryAttemptRef.current;
        if (attempt < INITIAL_LOAD_RETRY_DELAYS_MS.length) {
          retryAttemptRef.current += 1;
          retryTimerRef.current = window.setTimeout(() => {
            retryTimerRef.current = null;
            void loadRef.current?.(false, true);
          }, INITIAL_LOAD_RETRY_DELAYS_MS[attempt]);
        }
      }
    } finally {
      operationInFlight.current = false;
      setLoading(false);
    }
  }, [clearInitialLoadRetry, fetchPreference]);

  useEffect(() => {
    loadRef.current = load;
    return () => {
      loadRef.current = null;
    };
  }, [load]);

  useEffect(() => {
    viewRef.current = null;
    void load(true, true);
  }, [load]);

  useEffect(() => {
    onViewChange?.(view);
  }, [onViewChange, view]);

  useEffect(() => () => clearInitialLoadRetry(), [clearInitialLoadRetry]);

  useEffect(() => {
    if (view?.state !== 'switching' && view?.state !== 'rolling_back') return;
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load, view?.state]);

  const setPreferred = async (nodeId: string) => {
    if (operationInFlight.current) return;
    operationInFlight.current = true;
    setSubmittingNodeId(nodeId);
    try {
      const response = await api.post<unknown, ApiEnvelope<RelayPreferenceView>>(
        `/groups/${groupId}/relay-preference`,
        { node_id: nodeId },
      );
      if (response.code !== 0) throw new Error(response.message);
      setView(await fetchPreference());
      setLoadError(false);
      message.success(t('relaySwitchStarted'));
      return true;
    } catch (error) {
      message.error(requestErrorLabel(error, t));
      return false;
    } finally {
      operationInFlight.current = false;
      setSubmittingNodeId(null);
    }
  };

  const busy = loading || submittingNodeId !== null;
  const nodeById = new Map((view?.nodes ?? []).map((node) => [node.node_id, node]));
  const nodeLabel = (nodeId: string | null | undefined) => {
    if (!nodeId) return '-';
    return nodeById.get(nodeId)?.public_ipv4 ?? nodeId;
  };
  const catalogNames = new Map((carrierCatalog?.lines ?? []).map((line) => [line.id, line.name || line.id]));
  const activeCarrierBindings = carrierView?.active_policy.bindings ?? [];
  const followDefault = activeCarrierBindings.filter((binding) => binding.mode === 'follow_default');
  const explicit = activeCarrierBindings.filter((binding) => binding.mode === 'node');
  const topologyLocked = view?.state === 'switching'
    || view?.state === 'rolling_back'
    || view?.state === 'failed_manual_intervention';

  const switchImpact = (targetNodeId: string) => (
    <Space orientation="vertical" size={8} style={{ display: 'flex' }} data-testid="default-line-switch-impact">
      <Text>{t('relaySwitchImpactDefault')}: {nodeLabel(view?.preferred_node_id)} → {nodeLabel(targetNodeId)}</Text>
      {carrierAvailability === 'error' ? (
        <Alert type="warning" showIcon title={t('carrierPolicyUnavailable')} />
      ) : (
        <>
          <div>
            <Text strong>{t('relaySwitchImpactFollow')}</Text>
            {followDefault.length > 0
              ? followDefault.map((binding) => (
                <div key={binding.line_id}>{catalogNames.get(binding.line_id) ?? binding.line_id}: {nodeLabel(view?.preferred_node_id)} → {nodeLabel(targetNodeId)}</div>
              ))
              : <div><Text type="secondary">{t('relaySwitchImpactNone')}</Text></div>}
          </div>
          <div>
            <Text strong>{t('relaySwitchImpactExplicit')}</Text>
            {explicit.length > 0
              ? explicit.map((binding) => (
                <div key={binding.line_id}>{catalogNames.get(binding.line_id) ?? binding.line_id}: {t('relaySwitchImpactKeeps')} {nodeLabel(binding.node_id)}</div>
              ))
              : <div><Text type="secondary">{t('relaySwitchImpactNone')}</Text></div>}
          </div>
          <Text type="secondary">{t('relaySwitchImpactUnconfigured')}</Text>
        </>
      )}
    </Space>
  );

  const confirmSwitch = (node: RelayReadyNode) => {
    Modal.confirm({
      title: t('relaySwitchConfirmTitle'),
      content: switchImpact(node.node_id),
      okText: t('relaySwitchConfirm'),
      cancelText: t('cancel'),
      onOk: async () => {
        const succeeded = await setPreferred(node.node_id);
        if (!succeeded) throw new Error('switch request failed');
      },
    });
  };

  return (
    <div className="rp-default-line-panel" data-testid={`relay-preference-${groupId}`}>
      <Divider style={{ margin: '12px 0' }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
        <Space size={8} wrap>
          <Text strong>{t('defaultLineTitle')}</Text>
          {view?.preferred_node_id ? (
            <Text type="secondary" data-testid="relay-preference-current">
              {t('relayPreferenceCurrent')}: <Text code>{nodeLabel(view.preferred_node_id)}</Text>
            </Text>
          ) : null}
        </Space>
        <Tooltip title={t('refresh')}>
          <Button
            size="small"
            type="text"
            icon={<ReloadOutlined />}
            aria-label={t('refresh')}
            loading={loading && view !== null}
            disabled={submittingNodeId !== null}
            onClick={() => void load(true)}
          />
        </Tooltip>
      </div>

      {loading && !view ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> : null}
      {loadError && !view ? <Alert type="warning" showIcon title={t('relayPreferenceLoadFailed')} /> : null}
      {view?.state === 'switching' && view.pending_node_id ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 10 }}
          title={`${t('relayPreferenceSwitchingTo')}: ${view.pending_node_id ?? '-'}`}
          description={t('relayPreferenceSwitchingHint')}
        />
      ) : null}
      {view?.state === 'rolling_back' ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 10 }}
          title={t('relayPreferenceRollingBack')}
          description={`${t('relayPreferenceRollingBackHint')} · ${switchErrorLabel(view.last_error, t)}`}
        />
      ) : null}
      {view?.state === 'failed_rolled_back' ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 10 }}
          title={t('relayPreferenceRolledBack')}
          description={`${t('relayPreferenceLastTarget')}: ${view.pending_node_id ?? '-'} · ${switchErrorLabel(view.last_error, t)}`}
        />
      ) : null}
      {view?.state === 'failed_manual_intervention' ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 10 }}
          title={t('relayPreferenceManualIntervention')}
          description={`${switchErrorLabel(view.last_error, t)} · ${switchErrorLabel(view.rollback_error, t)}`}
        />
      ) : null}
      {view?.state === 'failed' ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 10 }}
          title={t('relayPreferenceSwitchFailed')}
          description={`${t('relayPreferenceLastTarget')}: ${view.pending_node_id ?? '-'} · ${switchErrorLabel(view.last_error, t)}`}
        />
      ) : null}

      {view && view.state !== 'idle' && view.state !== 'failed_manual_intervention' && carrierView?.transaction.kind !== 'carrier_policy_apply' && (view.dns_records ?? []).length > 0 ? (
        <div data-testid="relay-preference-dns-records" style={{ marginBottom: 10 }}>
          <Text strong>{t('relayPreferenceDnsRecords')}</Text>
          {(view.dns_records ?? []).map((record) => {
            const syncDisplay = dnsSyncStateDisplay(record.sync_state ?? '-', t);
            const lineLabel = record.line_key === 'default'
              ? t('relayPreferenceDefaultLine')
              : record.line_id;
            const positionLabel = record.position === 'rollback'
              ? t('relayPreferenceDnsAtPrevious')
              : record.position === 'target'
                ? t('relayPreferenceDnsAtTarget')
                : t('relayPreferenceDnsUnknown');
            const value = record.position === 'rollback'
              ? record.rollback_value
              : record.position === 'target'
                ? record.target_value
                : record.expected_value;
            return (
              <div
                key={`${record.rule_id}:${record.line_key}`}
                data-testid={`relay-dns-record-${record.rule_id}-${safeLineKey(record.line_key)}`}
                style={{ display: 'flex', flexWrap: 'wrap', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--rp-border)' }}
              >
                <Text code>{record.fqdn}</Text>
                <Tag>{lineLabel}</Tag>
                <Tag color={record.position === 'rollback' ? 'green' : record.position === 'target' ? 'orange' : 'red'}>
                  {positionLabel}
                </Tag>
                <Text type="secondary" className="rp-mono">{value ?? '-'}</Text>
                <Text type="secondary" data-raw-state={record.sync_state ?? '-'}>{syncDisplay.label}</Text>
                {record.last_error ? <Text type="danger">{record.last_error}</Text> : null}
              </div>
            );
          })}
        </div>
      ) : null}

      {view && view.nodes.length === 0 ? <Alert type="warning" showIcon title={t('relayPreferenceNoNodes')} /> : null}
      {view?.nodes.map((node) => {
        const reasons = node.ready_reasons.map((reason) => relayReadyReasonLabel(reason, t));
        const current = node.node_id === view.preferred_node_id;
        const isIdlePreferred = view.state === 'idle' && current;
        const showSwitchAction = !isIdlePreferred && (node.ready || view.state !== 'idle');
        const canSwitch = node.ready && !topologyLocked && !busy && carrierAvailability !== 'loading';
        return (
          <div className="rp-default-line-candidate" data-testid={`default-line-candidate-${node.node_id}`} key={node.node_id}>
            <div className="rp-default-line-candidate-main">
              <Space size={6} wrap>
                <Text strong className="rp-mono">{node.public_ipv4 ?? node.node_id}</Text>
                <Tag color={node.online ? 'green' : undefined}>{node.online ? t('online') : t('offline')}</Tag>
                <Tag color={node.ready ? 'green' : 'red'}>{node.ready ? t('relayReady') : t('relayNotReady')}</Tag>
                {current ? <Tag color="blue">{t('defaultLineCurrent')}</Tag> : null}
              </Space>
              {node.public_ipv4 ? <Text type="secondary" code>{node.node_id}</Text> : null}
              {!node.ready && reasons.length > 0 ? <Text type="danger">{reasons.join(' · ')}</Text> : null}
            </div>
            <Space size={4} wrap>
              {onDiagnoseNode ? (
                <Button size="small" icon={<MedicineBoxOutlined />} onClick={() => onDiagnoseNode(node)}>{t('diagnose')}</Button>
              ) : null}
              {showSwitchAction ? (
                <Button
                  size="small"
                  type="primary"
                  icon={<SwapOutlined />}
                  disabled={!canSwitch}
                  loading={submittingNodeId === node.node_id}
                  onClick={() => confirmSwitch(node)}
                >
                  {actionLabel(view, node, t)}
                </Button>
              ) : null}
            </Space>
          </div>
        );
      })}

      <Divider style={{ margin: '14px 0 10px' }} />
      <Text strong>{t('lineFeaturesTitle')}</Text>
      <Tabs
        className="rp-line-feature-tabs"
        defaultActiveKey="carrier"
        items={[
          {
            key: 'carrier',
            label: t('carrierAffinityTitle'),
            children: (
              <CarrierAffinityPanel
                groupId={groupId}
                nodes={view?.nodes ?? []}
                t={t}
                dnsRecords={view?.dns_records ?? []}
                onViewChange={setCarrierView}
                onCatalogChange={setCarrierCatalog}
                onAvailabilityChange={setCarrierAvailability}
              />
            ),
          },
          {
            key: 'schedule',
            label: t('relayScheduleTitle'),
            children: (
              <RelaySchedulePanel
                groupId={groupId}
                nodes={view?.nodes ?? []}
                t={t}
                carrierPolicy={carrierView?.active_policy}
                carrierCatalog={carrierCatalog}
                topologyState={view?.state}
              />
            ),
          },
        ]}
      />
    </div>
  );
}
