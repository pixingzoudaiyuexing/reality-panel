import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Divider, Modal, Space, Spin, Tabs, Tag, Tooltip, Typography, message } from 'antd';
import { MedicineBoxOutlined, ReloadOutlined, SaveOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type { ApiEnvelope, CarrierAffinityView, CarrierLineCatalog, RelayPreferenceView, RelayReadyNode, RoutingApplyRequest, RoutingApplyResult, RoutingMode } from '../../api/types';
import type { Tfn } from './types';
import { RelaySchedulePanel } from './RelaySchedulePanel';
import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { RelayFailoverPanel } from './RelayFailoverPanel';
import { relayReadyReasonLabel } from './shared';
import { dnsSyncStateDisplay } from '../../utils/realityRuleStatus';

const { Text } = Typography;

const INITIAL_LOAD_RETRY_DELAYS_MS = [2000, 5000] as const;
const ROUTING_APPLY_TIMEOUT_MS = 120000;
const UNKNOWN_OUTCOME_REFRESH_DELAYS_MS = [1000, 3000] as const;

type LoadPreference = (showSpinner?: boolean, allowInitialRetry?: boolean) => Promise<void>;

interface Props {
  groupId: number;
  t: Tfn;
  onDiagnoseNode?: (node: RelayReadyNode) => void;
  onViewChange?: (view: RelayPreferenceView | null) => void;
}

function switchErrorLabel(error: string | null, t: Tfn): string {
  if (!error) return t('relaySwitchUnknownError');
  if (error.startsWith('PUBLIC_DNS_')) return t('relaySwitchPublicDnsIgnored');
  const labels: Record<string, Parameters<Tfn>[0]> = {
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

function safeLineKey(lineKey: string): string {
  return lineKey.replace(/[^A-Za-z0-9_-]/g, '-');
}

function routingModeLabel(mode: RoutingMode, t: Tfn): string {
  const keys = {
    normal: 'routingMode_normal',
    carrier: 'routingMode_carrier',
    schedule: 'routingMode_schedule',
    failover: 'routingMode_failover',
  } as const;
  return t(keys[mode]);
}

function routingApplyErrorLabel(code: string | null | undefined, t: Tfn): string {
  const keys: Record<string, Parameters<Tfn>[0]> = {
    SCHEDULE_ENABLED_RULE_REQUIRED: 'routingErrorScheduleRequired',
    CARRIER_DEFAULT_REQUIRED: 'routingErrorCarrierDefaultRequired',
    CARRIER_DEFAULT_NOT_READY: 'routingErrorCarrierDefaultNotReady',
    NORMAL_DEFAULT_REQUIRED: 'routingErrorNormalDefaultRequired',
    NORMAL_DEFAULT_NOT_READY: 'routingErrorNormalDefaultNotReady',
    NORMAL_DEFAULT_INVALID: 'routingErrorNormalDefaultRequired',
    ROUTING_TRANSACTION_IN_PROGRESS: 'routingErrorTransactionInProgress',
    ROUTING_MODE_CONFLICT: 'routingErrorModeConflict',
    ROUTING_MODE_CHANGED: 'routingErrorModeChanged',
    DNSMGR_UNAVAILABLE: 'routingErrorDnsMgrUnavailable',
    DNS_PROVIDER_PREFLIGHT_FAILED: 'routingErrorProviderPreflight',
    DNS_OWNERSHIP_UNVERIFIED: 'routingErrorOwnership',
    CARRIER_CATALOG_UNAVAILABLE: 'carrierCatalogStale',
    CARRIER_POLICY_INVALID: 'carrierSaveFailed',
    CARRIER_TARGET_INVALID: 'routingErrorCarrierTargetInvalid',
    FAILOVER_CONFIG_INVALID: 'routingErrorFailoverInvalid',
    NO_ELIGIBLE_DNS_RULES: 'relaySwitchErrorNoRules',
  };
  return t(keys[code ?? ''] ?? 'routingApplyFailed');
}

export function RelayPreferencePanel({ groupId, t, onDiagnoseNode, onViewChange }: Props) {
  const [view, setView] = useState<RelayPreferenceView | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [submittingMode, setSubmittingMode] = useState<RoutingMode | null>(null);
  const [selectedMode, setSelectedMode] = useState<RoutingMode | null>(null);
  const [normalDraftNodeId, setNormalDraftNodeId] = useState<string | null>(null);
  const [dirtyModes, setDirtyModes] = useState<Partial<Record<RoutingMode, boolean>>>({});
  const [discardRevisions, setDiscardRevisions] = useState<Partial<Record<RoutingMode, number>>>({});
  const [carrierView, setCarrierView] = useState<CarrierAffinityView | null>(null);
  const [carrierCatalog, setCarrierCatalog] = useState<CarrierLineCatalog | null>(null);
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
    setSelectedMode(null);
    setNormalDraftNodeId(null);
    setDirtyModes({});
    setDiscardRevisions({});
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

  useEffect(() => {
    if (!view) return;
    if (selectedMode === null) setSelectedMode(view.active_routing_mode ?? 'normal');
    if (!dirtyModes.normal) {
      setNormalDraftNodeId(
        view.pending_routing_mode === null && view.state === 'switching'
          ? view.pending_node_id ?? view.normal_default_node_id ?? view.preferred_node_id
          : view.normal_default_node_id ?? view.preferred_node_id,
      );
    }
  }, [dirtyModes.normal, selectedMode, view]);

  const setModeDirty = (mode: RoutingMode, dirty: boolean) => {
    setDirtyModes((current) => current[mode] === dirty ? current : { ...current, [mode]: dirty });
  };

  const refreshPreferenceView = async (): Promise<RelayPreferenceView> => {
    const nextView = await fetchPreference();
    viewRef.current = nextView;
    setView(nextView);
    setLoadError(false);
    return nextView;
  };

  const recoverUnknownOutcome = async (targetMode: RoutingMode, activeModeBeforeRequest: RoutingMode | null) => {
    for (let attempt = 0; attempt <= UNKNOWN_OUTCOME_REFRESH_DELAYS_MS.length; attempt += 1) {
      if (attempt > 0) {
        await new Promise<void>((resolve) => {
          window.setTimeout(resolve, UNKNOWN_OUTCOME_REFRESH_DELAYS_MS[attempt - 1]);
        });
      }
      const nextView = await refreshPreferenceView().catch(() => null);
      if (!nextView) continue;
      const targetTransitionObserved = nextView.pending_routing_mode === targetMode
        || (activeModeBeforeRequest !== targetMode && nextView.active_routing_mode === targetMode)
        || (activeModeBeforeRequest === targetMode && nextView.state !== 'idle');
      if (targetTransitionObserved) return;
    }
  };

  const submitRoutingApply = async (request: RoutingApplyRequest): Promise<RoutingApplyResult | null> => {
    if (operationInFlight.current) return null;
    const mode = request.mode;
    const activeModeBeforeRequest = viewRef.current?.active_routing_mode ?? null;
    operationInFlight.current = true;
    setSubmittingMode(request.mode);
    try {
      let response: ApiEnvelope<RoutingApplyResult>;
      try {
        response = await api.put<unknown, ApiEnvelope<RoutingApplyResult>>(
          `/groups/${groupId}/routing-apply`,
          request,
          { timeout: ROUTING_APPLY_TIMEOUT_MS },
        );
        if (response.code !== 0 || !response.data) throw new Error(response.message);
      } catch (error) {
        const payload = (error as { response?: { data?: ApiEnvelope<RoutingApplyResult> } }).response?.data;
        const result = payload?.data;
        if (result) {
          await refreshPreferenceView().catch(() => null);
          if (result.config_saved) {
            setModeDirty(mode, false);
            const active = result.active_mode ? routingModeLabel(result.active_mode, t) : '-';
            message.warning(`${t('routingPartialFailure')} ${t('routingStillActive')}: ${active}. ${routingApplyErrorLabel(result.business_error_code, t)}`);
          } else {
            message.error(routingApplyErrorLabel(result.business_error_code, t));
          }
          return result;
        }
        message.warning(t('routingApplyOutcomeUnknown'));
        await recoverUnknownOutcome(mode, activeModeBeforeRequest);
        return null;
      }

      if (response.data.config_saved) setModeDirty(mode, false);
      message.success(t(response.data.transition_state === 'switching'
        ? response.data.activation_requested ? 'routingActivationStarted' : 'routingConfigurationApplying'
        : response.data.activation_requested
          ? 'routingActivationSucceeded'
          : 'routingConfigurationSaved'));
      try {
        await refreshPreferenceView();
      } catch {
        message.warning(t('routingRefreshFailedAfterSuccess'));
      }
      return response.data;
    } finally {
      operationInFlight.current = false;
      setSubmittingMode(null);
    }
  };

  const applyRouting = (request: RoutingApplyRequest): Promise<RoutingApplyResult | null> => {
    if (!view || request.mode === view.active_routing_mode) return submitRoutingApply(request);
    return new Promise((resolve) => {
      Modal.confirm({
        title: t('routingModeConfirmTitle'),
        content: `${t('routingEnableStopsCurrent')} ${routingModeLabel(view.active_routing_mode ?? 'normal', t)} → ${routingModeLabel(request.mode, t)}. ${t('routingPreviousConfigRetained')}`,
        okText: t('routingModeConfirm'),
        cancelText: t('cancel'),
        onCancel: () => resolve(null),
        onOk: async () => {
          resolve(await submitRoutingApply(request));
        },
      });
    });
  };

  const requestTabChange = (mode: RoutingMode) => {
    if (mode === selectedMode) return;
    const currentMode = selectedMode;
    if (!currentMode || !dirtyModes[currentMode]) {
      setSelectedMode(mode);
      return;
    }
    Modal.confirm({
      title: t('routingUnsavedTitle'),
      content: t('routingUnsavedDescription'),
      okText: t('routingDiscardChanges'),
      cancelText: t('routingContinueEditing'),
      okButtonProps: { danger: true },
      onOk: () => {
        setModeDirty(currentMode, false);
        if (currentMode === 'normal') {
          setNormalDraftNodeId(view?.normal_default_node_id ?? view?.preferred_node_id ?? null);
        } else {
          setDiscardRevisions((current) => ({
            ...current,
            [currentMode]: (current[currentMode] ?? 0) + 1,
          }));
        }
        setSelectedMode(mode);
      },
    });
  };

  const busy = loading || submittingMode !== null;
  const modeConflict = (view?.routing_mode_conflict?.length ?? 0) > 1;
  const activeMode = view?.active_routing_mode ?? 'normal';
  const nodeById = new Map((view?.nodes ?? []).map((node) => [node.node_id, node]));
  const nodeLabel = (nodeId: string | null | undefined) => {
    if (!nodeId) return '-';
    return nodeById.get(nodeId)?.public_ipv4 ?? nodeId;
  };
  const topologyLocked = view?.state === 'switching'
    || view?.state === 'rolling_back'
    || view?.state === 'failed_manual_intervention';
  const normalSavedNodeId = view?.normal_default_node_id ?? view?.preferred_node_id ?? null;
  const normalActive = activeMode === 'normal';
  const normalCanSubmit = Boolean(normalDraftNodeId)
    && !modeConflict
    && !topologyLocked
    && !busy
    && (!normalActive || Boolean(dirtyModes.normal));

  return (
    <div className="rp-default-line-panel" data-testid={`relay-preference-${groupId}`}>
      <Divider style={{ margin: '12px 0' }} />
      <div className="rp-routing-mode-control" data-testid="routing-mode-control">
        <Space size={8} wrap>
          <Text strong>{t('lineFeaturesTitle')}</Text>
          <Text type="secondary">{t('routingModeCurrent')}</Text>
          {!modeConflict ? <Tag color="blue">{routingModeLabel(activeMode, t)}</Tag> : null}
          {view?.pending_routing_mode && view.state === 'switching' ? <Tag color="processing">{t('routingModeSwitching')}: {routingModeLabel(view.pending_routing_mode, t)}</Tag> : null}
          {view?.pending_routing_mode && view.state === 'rolling_back' ? <Tag color="warning">{t('routingModeRollingBack')}: {routingModeLabel(view.pending_routing_mode, t)}</Tag> : null}
        </Space>
        <Tooltip title={t('refresh')}>
          <Button
            size="small"
            type="text"
            icon={<ReloadOutlined />}
            aria-label={t('refresh')}
            loading={loading && view !== null}
            disabled={submittingMode !== null}
            onClick={() => void load(true)}
          />
        </Tooltip>
      </div>
      {modeConflict ? <Alert type="error" showIcon title={t('routingModeConflict')} style={{ marginBottom: 12 }} /> : null}

      {loading && !view ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> : null}
      {loadError && !view ? <Alert type="warning" showIcon title={t('relayPreferenceLoadFailed')} /> : null}
      {view?.state === 'switching' && view.pending_node_id && !view.pending_routing_mode ? (
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

      <Tabs
        className="rp-line-feature-tabs"
        activeKey={selectedMode ?? activeMode}
        onChange={(mode) => requestTabChange(mode as RoutingMode)}
        items={[
          {
            key: 'normal',
            label: t('routingFunctionNormal'),
            children: (
              <section className="rp-line-feature-section" data-testid="normal-routing-panel">
                <div className="rp-section-heading">
                  <Space size={8} wrap>
                    <Tag color={normalActive ? 'green' : undefined}>{t(normalActive ? 'routingModeActive' : 'routingModeInactive')}</Tag>
                    {view?.preferred_node_id ? (
                      <Text type="secondary" data-testid="relay-preference-current">
                        {t('relayPreferenceCurrent')}: <Text code>{nodeLabel(view.preferred_node_id)}</Text>
                      </Text>
                    ) : null}
                  </Space>
                  <Button
                    size="small"
                    type="primary"
                    icon={<SaveOutlined />}
                    data-testid="normal-routing-apply"
                    disabled={!normalCanSubmit}
                    loading={submittingMode === 'normal'}
                    onClick={() => normalDraftNodeId && void applyRouting({ mode: 'normal', default_node_id: normalDraftNodeId })}
                  >
                    {t(normalActive ? 'routingSaveChanges' : 'routingSaveAndActivate')}
                  </Button>
                </div>
                {view && view.nodes.length === 0 ? <Alert type="warning" showIcon title={t('relayPreferenceNoNodes')} /> : null}
                {view?.nodes.map((node) => {
                  const reasons = node.ready_reasons.map((reason) => relayReadyReasonLabel(reason, t));
                  const effective = node.node_id === view.preferred_node_id;
                  const selected = node.node_id === normalDraftNodeId;
                  return (
                    <div className="rp-default-line-candidate" data-testid={`default-line-candidate-${node.node_id}`} key={node.node_id}>
                      <div className="rp-default-line-candidate-main">
                        <Space size={6} wrap>
                          <Text strong className="rp-mono">{node.public_ipv4 ?? node.node_id}</Text>
                          <Tag color={node.online ? 'green' : undefined}>{node.online ? t('online') : t('offline')}</Tag>
                          <Tag color={node.ready ? 'green' : 'red'}>{node.ready ? t('relayReady') : t('relayNotReady')}</Tag>
                          {effective ? <Tag>{t('routingEffectiveDefault')}</Tag> : null}
                          {selected ? <Tag color="blue">{t('routingNormalSelected')}</Tag> : null}
                        </Space>
                        {node.public_ipv4 ? <Text type="secondary" code>{node.node_id}</Text> : null}
                        {!node.ready && reasons.length > 0 ? <Text type="danger">{reasons.join(' · ')}</Text> : null}
                      </div>
                      <Space size={4} wrap>
                        {onDiagnoseNode ? (
                          <Button size="small" icon={<MedicineBoxOutlined />} onClick={() => onDiagnoseNode(node)}>{t('diagnose')}</Button>
                        ) : null}
                        {!selected && node.ready ? (
                          <Button
                            size="small"
                            disabled={topologyLocked || busy || modeConflict}
                            onClick={() => {
                              setNormalDraftNodeId(node.node_id);
                              setModeDirty('normal', node.node_id !== normalSavedNodeId);
                            }}
                          >
                            {t('routingSetNormalDefault')}
                          </Button>
                        ) : null}
                      </Space>
                    </div>
                  );
                })}
              </section>
            ),
          },
          {
            key: 'carrier',
            label: t('routingFunctionCarrier'),
            children: (
              <CarrierAffinityPanel
                key={`carrier-${discardRevisions.carrier ?? 0}`}
                groupId={groupId}
                nodes={view?.nodes ?? []}
                t={t}
                dnsRecords={view?.dns_records ?? []}
                onViewChange={setCarrierView}
                onCatalogChange={setCarrierCatalog}
                activeMode={activeMode}
                disabled={modeConflict || topologyLocked}
                onApply={applyRouting}
                onDirtyChange={(dirty) => setModeDirty('carrier', dirty)}
              />
            ),
          },
          {
            key: 'schedule',
            label: t('routingFunctionSchedule'),
            children: (
              <RelaySchedulePanel
                key={`schedule-${discardRevisions.schedule ?? 0}`}
                groupId={groupId}
                nodes={view?.nodes ?? []}
                t={t}
                carrierPolicy={carrierView?.active_policy}
                carrierCatalog={carrierCatalog}
                topologyState={view?.state}
                active={activeMode === 'schedule'}
                disabled={modeConflict || topologyLocked || busy}
                activating={submittingMode === 'schedule'}
                onActivate={() => applyRouting({ mode: 'schedule' })}
              />
            ),
          },
          {
            key: 'failover',
            label: t('routingFunctionFailover'),
            children: (
              <RelayFailoverPanel
                key={`failover-${discardRevisions.failover ?? 0}`}
                groupId={groupId}
                t={t}
                active={activeMode === 'failover'}
                disabled={modeConflict || topologyLocked}
                onApply={applyRouting}
                onDirtyChange={(dirty) => setModeDirty('failover', dirty)}
              />
            ),
          },
        ]}
      />
    </div>
  );
}
