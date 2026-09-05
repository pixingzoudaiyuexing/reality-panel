import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, InputNumber, Space, Spin, Switch, Tag, Typography, message } from 'antd';
import { SaveOutlined, UndoOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type { ApiEnvelope, RelayFailoverView } from '../../api/types';
import type { Tfn } from './types';
import { relayReadyReasonLabel } from './shared';

const { Text } = Typography;

interface Props {
  groupId: number;
  t: Tfn;
}

function requestError(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { message?: string } } }).response?.data?.message;
  return detail ? `${fallback}: ${detail}` : fallback;
}

function resultLabel(result: string, t: Tfn): string {
  const keys: Record<string, Parameters<Tfn>[0]> = {
    started: 'relayFailoverResult_started',
    success: 'relayFailoverResult_success',
    failed: 'relayFailoverResult_failed',
    exhausted: 'relayFailoverResult_exhausted',
    aborted: 'relayFailoverResult_aborted',
  };
  const key = keys[result];
  return key ? t(key) : result;
}

function errorLabel(error: string, t: Tfn): string {
  return error === 'NO_AVAILABLE_CANDIDATES' ? t('relayFailoverNoCandidates') : error;
}

export function RelayFailoverPanel({ groupId, t }: Props) {
  const [view, setView] = useState<RelayFailoverView | null>(null);
  const [port, setPort] = useState<number>(443);
  const [failureAfter, setFailureAfter] = useState<number>(5);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const [reincluding, setReincluding] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const dirtyRef = useRef(false);

  const applyView = useCallback((next: RelayFailoverView, keepInputs = false) => {
    setView(next);
    if (!keepInputs) {
      setPort(next.health_check_port);
      setFailureAfter(next.failure_after_seconds);
      setDirty(false);
      dirtyRef.current = false;
    }
  }, []);

  const load = useCallback(async (background = false) => {
    if (!background) setLoading(true);
    try {
      const response = await api.get<unknown, ApiEnvelope<RelayFailoverView>>(
        `/groups/${groupId}/relay-failover`,
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      applyView(response.data, background && dirtyRef.current);
      setLoadError(false);
    } catch {
      if (!background) setLoadError(true);
    } finally {
      if (!background) setLoading(false);
    }
  }, [applyView, groupId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!view?.enabled) return;
    const timer = window.setInterval(() => void load(true), 2000);
    return () => window.clearInterval(timer);
  }, [load, view?.enabled]);

  const update = async (enabled: boolean) => {
    setSaving(true);
    try {
      const response = await api.put<unknown, ApiEnvelope<RelayFailoverView>>(
        `/groups/${groupId}/relay-failover`,
        {
          enabled,
          health_check_port: port,
          failure_after_seconds: failureAfter,
        },
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      applyView(response.data);
      message.success(t('relayFailoverSaved'));
    } catch (error) {
      message.error(requestError(error, t('relayFailoverSaveFailed')));
    } finally {
      setSaving(false);
    }
  };

  const reinclude = async (nodeId: string) => {
    setReincluding(nodeId);
    try {
      const response = await api.post<unknown, ApiEnvelope<RelayFailoverView>>(
        `/groups/${groupId}/relay-failover/reinclude`,
        { node_id: nodeId },
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      applyView(response.data, dirtyRef.current);
      message.success(t('relayFailoverReincluded'));
    } catch (error) {
      message.error(requestError(error, t('relayFailoverReincludeFailed')));
    } finally {
      setReincluding(null);
    }
  };

  if (loading && !view) {
    return <div style={{ textAlign: 'center', padding: 12 }}><Spin size="small" /></div>;
  }

  return (
    <section data-testid={`relay-failover-${groupId}`} className="rp-line-feature-section">
      {loadError && !view ? (
        <Alert
          type="warning"
          showIcon
          title={t('relayFailoverLoadFailed')}
          action={<Button size="small" onClick={() => void load()}>{t('refresh')}</Button>}
        />
      ) : null}
      {view ? (
        <>
          <div className="rp-failover-settings">
            <div className="rp-failover-setting">
              <Text>{t('relayFailoverEnabled')}</Text>
              <Switch
                aria-label={t('relayFailoverEnabled')}
                checked={view.enabled}
                loading={saving}
                onChange={(checked) => void update(checked)}
              />
            </div>
            <div className="rp-failover-setting">
              <Text>{t('relayFailoverHealthCheck')}</Text>
              <Tag>TCP</Tag>
            </div>
            <div className="rp-failover-setting">
              <Text>{t('relayFailoverPort')}</Text>
              <InputNumber
                aria-label={t('relayFailoverPort')}
                min={1}
                max={65535}
                precision={0}
                value={port}
                onChange={(value) => {
                  if (value !== null) setPort(value);
                  setDirty(true);
                  dirtyRef.current = true;
                }}
              />
            </div>
            <div className="rp-failover-setting">
              <Text>{t('relayFailoverFailureAfter')}</Text>
              <Space size={6}>
                <InputNumber
                  aria-label={t('relayFailoverFailureAfter')}
                  min={1}
                  max={86400}
                  precision={0}
                  value={failureAfter}
                  onChange={(value) => {
                    if (value !== null) setFailureAfter(value);
                    setDirty(true);
                    dirtyRef.current = true;
                  }}
                />
                <Text type="secondary">{t('seconds')}</Text>
              </Space>
            </div>
            <Button
              size="small"
              type="primary"
              icon={<SaveOutlined />}
              disabled={!dirty || port < 1 || port > 65535 || failureAfter < 1 || failureAfter > 86400}
              loading={saving}
              onClick={() => void update(view.enabled)}
            >
              {t('save')}
            </Button>
          </div>

          <Alert
            type="info"
            showIcon
            title={t('relayFailoverDescription')}
            style={{ margin: '10px 0' }}
          />
          {view.last_result === 'exhausted' ? (
            <Alert
              type="error"
              showIcon
              title={t('relayFailoverResult_exhausted')}
              description={t('relayFailoverNoCandidates')}
              style={{ marginBottom: 10 }}
            />
          ) : null}
          <Space size={6} wrap style={{ marginBottom: 8 }}>
            <Text type="secondary">{t('relayFailoverCurrent')}:</Text>
            <Text code>{view.current_node_id ?? '-'}</Text>
            {view.last_result ? <Tag>{resultLabel(view.last_result, t)}</Tag> : null}
            {view.last_error ? <Text type="danger">{errorLabel(view.last_error, t)}</Text> : null}
          </Space>

          {view.nodes.map((node) => {
            const role = node.current
              ? t('relayFailoverCurrentInUse')
              : node.excluded
                ? t('relayFailoverExcluded')
                : node.ready
                  ? t('relayFailoverStandby')
                  : t('relayFailoverNotReady');
            const probe = node.probe_status === 'healthy'
              ? t('relayFailoverProbeHealthy')
              : node.probe_status === 'unhealthy'
                ? t('relayFailoverProbeUnhealthy')
                : t('relayFailoverProbeUnknown');
            return (
              <div className="rp-default-line-candidate" data-testid={`relay-failover-node-${node.node_id}`} key={node.node_id}>
                <div className="rp-default-line-candidate-main">
                  <Space size={6} wrap>
                    <Text strong className="rp-mono">{node.public_ipv4 ?? node.node_id}</Text>
                    <Tag color={node.current ? 'blue' : node.excluded ? 'red' : node.ready ? 'green' : undefined}>{role}</Tag>
                    <Tag color={node.probe_status === 'healthy' ? 'green' : node.probe_status === 'unhealthy' ? 'red' : undefined}>{probe}</Tag>
                  </Space>
                  {node.public_ipv4 ? <Text type="secondary" code>{node.node_id}</Text> : null}
                  {!node.ready && node.ready_reasons.length > 0 ? (
                    <Text type="danger">{node.ready_reasons.map((reason) => relayReadyReasonLabel(reason, t)).join(' · ')}</Text>
                  ) : null}
                </div>
                {node.excluded ? (
                  <Button
                    size="small"
                    icon={<UndoOutlined />}
                    loading={reincluding === node.node_id}
                    onClick={() => void reinclude(node.node_id)}
                  >
                    {t('relayFailoverReinclude')}
                  </Button>
                ) : null}
              </div>
            );
          })}
        </>
      ) : null}
    </section>
  );
}
