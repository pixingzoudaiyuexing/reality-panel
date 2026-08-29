import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Divider, Empty, Space, Spin, Tag, Tooltip, Typography, message } from 'antd';
import { ReloadOutlined, SwapOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type { ApiEnvelope, RelayPreferenceView, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';

const { Text } = Typography;

interface Props {
  groupId: number;
  t: Tfn;
}

function readyReasonLabel(reason: string, t: Tfn): string {
  const [code, detail] = reason.split(':', 2);
  const labels: Record<string, Parameters<Tfn>[0]> = {
    STATUS_MISSING: 'relayReadyStatusMissing',
    STATUS_INVALID: 'relayReadyStatusInvalid',
    STALE_STATUS: 'relayReadyStaleStatus',
    LAST_SEEN_MISSING: 'relayReadyLastSeenMissing',
    CONTROL_CHANNEL_OFFLINE: 'relayReadyControlOffline',
    CONFIG_PROTOCOL_MISMATCH: 'relayReadyProtocolMismatch',
    PUBLIC_IPV4_INVALID: 'relayReadyIpv4Invalid',
    PUBLIC_IPV4_MISSING: 'relayReadyIpv4Missing',
    RECONCILIATION_NOT_CONVERGED: 'relayReadyNotConverged',
    ACTIVE_RULES_MISSING: 'relayReadyActiveRulesMissing',
    ACTIVE_RULE_MISSING: 'relayReadyActiveRuleMissing',
    CAMOUFLAGE_SITE_NOT_ACTIVE: 'relayReadyCamouflageInactive',
    CERTIFICATE_NOT_ACTIVE: 'relayReadyCertificateInactive',
    LISTENER_ERROR: 'relayReadyListenerError',
  };
  const key = labels[code];
  if (!key) return reason;
  return detail ? `${t(key)} (${detail})` : t(key);
}

function switchErrorLabel(error: string | null, t: Tfn): string {
  if (!error) return t('relaySwitchUnknownError');
  const labels: Record<string, Parameters<Tfn>[0]> = {
    PUBLIC_DNS_MULTIPLE_ANSWERS: 'relaySwitchErrorMultipleAnswers',
    DNS_RECORD_CONFLICT: 'relaySwitchErrorRecordConflict',
    TARGET_STATUS_UNAVAILABLE: 'relaySwitchErrorTargetStatus',
    TARGET_PUBLIC_IPV4_UNAVAILABLE: 'relaySwitchErrorTargetIpv4',
    TARGET_NOT_READY_AFTER_DNS: 'relaySwitchErrorTargetNotReady',
    DNS_SCHEDULING_FAILED: 'relaySwitchErrorScheduling',
    MUTATION_OUTCOME_UNKNOWN: 'relaySwitchErrorMutationUnknown',
    DISABLED: 'relaySwitchErrorDisabled',
    NO_ELIGIBLE_DNS_RULES: 'relaySwitchErrorNoRules',
    PENDING_NODE_MISSING: 'relaySwitchErrorPendingMissing',
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
  if (view.state === 'switching') {
    return node.node_id === view.pending_node_id
      ? t('relayPreferenceSwitching')
      : t('relayPreferenceSwitchLocked');
  }
  if (view.state === 'failed') {
    if (node.node_id === view.pending_node_id) return t('relayPreferenceRetry');
    if (node.node_id === view.preferred_node_id) return t('relayPreferenceReconfirm');
  }
  return t('relayPreferenceSet');
}

export function RelayPreferencePanel({ groupId, t }: Props) {
  const [view, setView] = useState<RelayPreferenceView | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [submittingNodeId, setSubmittingNodeId] = useState<string | null>(null);
  const requestInFlight = useRef(false);

  const load = useCallback(async (showSpinner = false) => {
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    if (showSpinner) setLoading(true);
    try {
      const response = await api.get<unknown, ApiEnvelope<RelayPreferenceView>>(
        `/groups/${groupId}/relay-preference`,
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setView(response.data);
      setLoadError(false);
    } catch {
      setLoadError(true);
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    void load(true);
  }, [load]);

  useEffect(() => {
    if (view?.state !== 'switching') return;
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load, view?.state]);

  const setPreferred = async (nodeId: string) => {
    setSubmittingNodeId(nodeId);
    try {
      const response = await api.post<unknown, ApiEnvelope<RelayPreferenceView>>(
        `/groups/${groupId}/relay-preference`,
        { node_id: nodeId },
      );
      if (response.code !== 0) throw new Error(response.message);
      await load();
      message.success(t('relaySwitchStarted'));
    } catch (error) {
      message.error(requestErrorLabel(error, t));
    } finally {
      setSubmittingNodeId(null);
    }
  };

  return (
    <div style={{ padding: '0 12px 12px' }} data-testid={`relay-preference-${groupId}`}>
      <Divider style={{ margin: '12px 0' }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
        <Space size={8} wrap>
          <Text strong>{t('relayPreferenceTitle')}</Text>
          {view?.preferred_node_id ? (
            <Text type="secondary">{t('relayPreferenceCurrent')}: <Text code>{view.preferred_node_id}</Text></Text>
          ) : null}
        </Space>
        <Tooltip title={t('refresh')}>
          <Button
            size="small"
            type="text"
            icon={<ReloadOutlined />}
            aria-label={t('refresh')}
            loading={loading && view !== null}
            onClick={() => void load(true)}
          />
        </Tooltip>
      </div>

      {loading && !view ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> : null}
      {loadError && !view ? <Alert type="warning" showIcon title={t('relayPreferenceLoadFailed')} /> : null}
      {view?.state === 'switching' ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 10 }}
          title={`${t('relayPreferenceSwitchingTo')}: ${view.pending_node_id ?? '-'}`}
          description={t('relayPreferenceSwitchingHint')}
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

      {view && view.nodes.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('relayPreferenceNoNodes')} /> : null}
      {view && view.nodes.length > 0 ? (
        <div>
          {view.nodes.map((node) => {
            const isIdlePreferred = view.state === 'idle' && node.node_id === view.preferred_node_id;
            const disabled = !node.ready || view.state === 'switching';
            return (
              <div
                key={node.node_id}
                data-testid={`relay-preference-node-${node.node_id}`}
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  gap: 12,
                  minHeight: 64,
                  padding: '10px 0',
                  borderBottom: '1px solid var(--rp-border)',
                }}
              >
                <div style={{ flex: '1 1 420px', minWidth: 0 }}>
                  <Space size={6} wrap>
                    <Text code>{node.node_id}</Text>
                    <Tag color={node.online ? 'green' : undefined}>{node.online ? t('online') : t('offline')}</Tag>
                    <Tag color={node.ready ? 'green' : 'red'}>{node.ready ? t('relayReady') : t('relayNotReady')}</Tag>
                    {node.node_id === view.preferred_node_id ? <Tag color="blue">{t('relayPreferenceCurrent')}</Tag> : null}
                    {node.node_id === view.pending_node_id ? (
                      <Tag color={view.state === 'switching' ? 'processing' : 'error'}>
                        {view.state === 'switching' ? t('relayPreferencePending') : t('relayPreferenceLastTarget')}
                      </Tag>
                    ) : null}
                  </Space>
                  <Space orientation="vertical" size={2} style={{ display: 'flex', marginTop: 4 }}>
                    <Text type="secondary" className="rp-mono">{node.public_ipv4 ?? '-'}</Text>
                    {!node.ready && node.ready_reasons.length > 0 ? (
                      <Text type="danger">{node.ready_reasons.map((reason) => readyReasonLabel(reason, t)).join('; ')}</Text>
                    ) : null}
                  </Space>
                </div>
                {!isIdlePreferred ? (
                  <Button
                    size="small"
                    type={view.state === 'failed' && node.ready ? 'default' : 'primary'}
                    icon={<SwapOutlined />}
                    disabled={disabled}
                    loading={submittingNodeId === node.node_id}
                    onClick={() => void setPreferred(node.node_id)}
                  >
                    {actionLabel(view, node, t)}
                  </Button>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
