import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Divider, Empty, Popconfirm, Select, Space, Spin, Tag, Typography, message } from 'antd';
import { DeleteOutlined, PlusOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import axios from 'axios';
import api from '../../api/client';
import type { ApiEnvelope, DeviceGroup, NodeReusePreview, NodeReuseRuntimeStatus, NodeReuseSyncState } from '../../api/types';
import { useI18n } from '../../i18n/context';

interface Props {
  homeGroupId: number;
  nodeId: string;
  open: boolean;
}

const syncColors: Record<NodeReuseSyncState, string> = {
  NOT_READY: 'default',
  WAITING: 'processing',
  SYNCED: 'success',
  OFFLINE: 'default',
  CONFLICT: 'error',
  APPLY_FAILED: 'error',
  DEGRADED: 'warning',
};

function apiErrorCode(error: unknown): string | null {
  if (!axios.isAxiosError(error)) return null;
  const body = error.response?.data;
  return typeof body?.message === 'string' ? body.message : null;
}

export function NodeReusePanel({ homeGroupId, nodeId, open }: Props) {
  const { t } = useI18n();
  const [runtime, setRuntime] = useState<NodeReuseRuntimeStatus | null>(null);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [groupsError, setGroupsError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [adding, setAdding] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState<number | null>(null);
  const [preview, setPreview] = useState<NodeReusePreview | null>(null);
  const [previewForGroupId, setPreviewForGroupId] = useState<number | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [saving, setSaving] = useState(false);
  const [removingId, setRemovingId] = useState<number | null>(null);
  const requestId = useRef(0);
  const previewRequestId = useRef(0);

  const statusUrl = `/admin/node-reuse/nodes/${homeGroupId}/${encodeURIComponent(nodeId)}/runtime-status`;
  const refresh = useCallback(async () => {
    const current = ++requestId.current;
    try {
      const response = await api.get<unknown, ApiEnvelope<NodeReuseRuntimeStatus>>(statusUrl);
      if (current !== requestId.current) return null;
      if (response.code !== 0 || !response.data) throw new Error('status unavailable');
      setRuntime(response.data);
      setLoadError(false);
      return response.data;
    } catch {
      if (current === requestId.current) {
        setRuntime(null);
        setLoadError(true);
      }
      return null;
    } finally {
      if (current === requestId.current) setLoading(false);
    }
  }, [statusUrl]);

  const loadGroups = useCallback(async () => {
    try {
      const response = await api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups');
      if (response.code !== 0 || !response.data) throw new Error('groups unavailable');
      setGroups(response.data);
      setGroupsError(false);
    } catch {
      setGroups([]);
      setGroupsError(true);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setRuntime(null);
    setLoadError(false);
    setGroups([]);
    setGroupsError(false);
    setAdding(false);
    setSelectedGroupId(null);
    setPreview(null);
    setPreviewForGroupId(null);
    previewRequestId.current += 1;
    void refresh();
    void loadGroups();
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => { window.clearInterval(timer); requestId.current += 1; previewRequestId.current += 1; };
  }, [open, loadGroups, refresh]);

  const groupNames = useMemo(
    () => new Map(groups.map((group) => [group.id, group.name])),
    [groups],
  );
  const boundIds = useMemo(
    () => new Set(runtime?.bindings.map((item) => item.binding.reusing_group_id) ?? []),
    [runtime],
  );
  const eligibleGroups = groups.filter((group) =>
    group.group_type === 'in' && group.id !== homeGroupId && !boundIds.has(group.id),
  );

  const errorText = (error: unknown) => {
    const code = apiErrorCode(error);
    if (code === 'CURRENT_ACTIVE_CREDENTIAL_REQUIRED') return t('nodeReuseCredentialRequired');
    if (code === 'CONFIG_CONFLICT') return t('nodeReuseConflictGeneric');
    if (code === 'REUSING_GROUP_NOT_INBOUND' || code === 'REUSING_GROUP_NOT_FOUND') {
      return t('nodeReuseGroupUnavailable');
    }
    if (code?.startsWith('PREVIEW_SOURCE_CONFIG_INVALID') || code?.startsWith('INVALID_STORED_SOURCE')) {
      return t('nodeReuseSourceInvalid');
    }
    return t('nodeReuseCheckFailed');
  };

  const runPreflight = async () => {
    if (selectedGroupId === null) return;
    const checkedGroupId = selectedGroupId;
    const checkId = ++previewRequestId.current;
    setChecking(true);
    setPreview(null);
    setPreviewForGroupId(null);
    setPreviewError(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<NodeReusePreview>>(
        '/admin/node-reuse/bindings/preview',
        { reusing_group_id: checkedGroupId, home_group_id: homeGroupId, node_id: nodeId },
      );
      if (checkId !== previewRequestId.current) return;
      if (response.code !== 0 || !response.data) throw new Error('preflight unavailable');
      setPreview(response.data);
      setPreviewForGroupId(checkedGroupId);
    } catch (error) {
      if (checkId === previewRequestId.current) setPreviewError(errorText(error));
    } finally {
      if (checkId === previewRequestId.current) setChecking(false);
    }
  };

  const create = async () => {
    if (selectedGroupId === null || previewForGroupId !== selectedGroupId
      || !preview?.known_runtime_prerequisites_satisfied || preview.conflicts.length) return;
    setSaving(true);
    try {
      await api.post('/admin/node-reuse/bindings', {
        reusing_group_id: selectedGroupId, home_group_id: homeGroupId, node_id: nodeId,
      });
      setAdding(false);
      setPreview(null);
      setPreviewForGroupId(null);
      setSelectedGroupId(null);
      const latest = await refresh();
      message.success(latest?.sync_state === 'OFFLINE' ? t('nodeReuseSavedOffline') : t('nodeReuseSavedWaiting'));
    } catch (error) {
      setPreviewError(errorText(error));
      setPreview(null);
      setPreviewForGroupId(null);
    } finally {
      setSaving(false);
    }
  };

  const remove = async (reusingGroupId: number) => {
    setRemovingId(reusingGroupId);
    try {
      await api.delete(`/admin/node-reuse/bindings/${reusingGroupId}/${homeGroupId}/${encodeURIComponent(nodeId)}`);
      const latest = await refresh();
      message.info(latest?.sync_state === 'OFFLINE' ? t('nodeReuseRemovedOffline') : t('nodeReuseRemovedWaiting'));
    } catch {
      message.error(t('nodeReuseRemoveFailed'));
    } finally {
      setRemovingId(null);
    }
  };

  const conflictText = (conflict: NodeReusePreview['conflicts'][number], candidate: NodeReusePreview) => {
    const listener = candidate.listeners.find((item) => item.source_group_id === conflict.source_group_id
      && item.rule_id === conflict.rule_id);
    return listener
      ? t('nodeReusePortConflict').replace('{port}', String(listener.port)).replace('{protocol}', listener.protocol)
      : t('nodeReuseConflictGeneric');
  };

  return (
    <section aria-label={t('nodeReuseTitle')} style={{ marginTop: 24 }}>
      <Divider titlePlacement="start">{t('nodeReuseTitle')}</Divider>
      {loading && !runtime ? <Spin /> : null}
      {loadError ? (
        <Alert type="error" showIcon title={t('nodeReuseStatusUnavailable')}
          action={<Button size="small" icon={<ReloadOutlined />} onClick={() => { void refresh(); }} aria-label={t('refresh')} />} />
      ) : null}
      {runtime ? (
        <>
          <Space wrap style={{ marginBottom: 12 }}>
            <Typography.Text>{t('nodeReuseReadiness')}</Typography.Text>
            <Tag color={runtime.ready ? 'success' : 'default'}>
              {runtime.ready ? t('nodeReuseReady') : t('nodeReuseNotReady')}
            </Tag>
            <Tag color={syncColors[runtime.sync_state]}>{t(`nodeReuseState_${runtime.sync_state}`)}</Tag>
          </Space>
          {!runtime.ready ? (
            <Alert type="info" showIcon title={t('nodeReuseNotReadyImpact')}
              description={<details><summary>{t('nodeReuseRequirements')}</summary>
                {runtime.blockers.includes('ACTIVE_CREDENTIAL_MISSING') ? t('nodeReuseCredentialRequired')
                  : runtime.blockers.includes('NODE_NOT_VERIFIED_IN_LAST_REPORT') ? t('nodeReuseVerifiedRequired')
                    : t('nodeReuseStatusUnavailable')}
              </details>} />
          ) : null}
          {runtime.sync_state === 'OFFLINE' ? <Alert type="warning" showIcon title={t('nodeReuseOfflineImpact')} /> : null}
          {runtime.sync_state === 'APPLY_FAILED' ? <Alert type="error" showIcon title={t('nodeReuseApplyFailureImpact')} /> : null}
          {runtime.sync_state === 'DEGRADED' ? <Alert type="warning" showIcon title={t('nodeReuseDegradedImpact')} /> : null}
          {runtime.sync_state === 'CONFLICT' ? <Alert type="error" showIcon title={t('nodeReuseConflictImpact')}
            description={runtime.preview?.conflicts.map((conflict, index) => (
              <div key={`${conflict.kind}-${index}`}>{conflictText(conflict, runtime.preview!)}</div>
            ))} /> : null}
          <Typography.Title level={5} style={{ marginTop: 20 }}>{t('nodeReuseCurrentGroups')}</Typography.Title>
          {runtime.bindings.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('nodeReuseNoBindings')} /> : (
            <div>
              {runtime.bindings.map(({ binding }) => {
                const source = runtime.preview?.sources.find((item) => item.group_id === binding.reusing_group_id);
                return (
                  <div key={binding.reusing_group_id} style={{ display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--ant-color-border-secondary)', padding: '10px 0', flexWrap: 'wrap' }}>
                    <div>
                      <Typography.Text strong>{groupNames.get(binding.reusing_group_id) ?? `Group ${binding.reusing_group_id}`}</Typography.Text>
                      <div><Typography.Text type="secondary">{t('nodeReuseBindingSaved')}{source ? ` · ${t('nodeReuseRules').replace('{count}', String(source.rule_ids.length))}` : ''}</Typography.Text></div>
                    </div>
                    <Popconfirm title={t('nodeReuseRemoveConfirm')}
                      description={runtime.sync_state === 'OFFLINE' ? t('nodeReuseRemovedOffline') : t('nodeReuseRemoveImpact')}
                      onConfirm={() => { void remove(binding.reusing_group_id); }}>
                      <Button danger size="small" icon={<DeleteOutlined />} loading={removingId === binding.reusing_group_id}>{t('nodeReuseRemove')}</Button>
                    </Popconfirm>
                  </div>
                );
              })}
            </div>
          )}
          <div style={{ marginTop: 16 }}>
            <Button icon={<PlusOutlined />} disabled={!runtime.ready || eligibleGroups.length === 0}
              onClick={() => { setAdding(true); setPreview(null); setPreviewError(null); }}>
              {t('nodeReuseAdd')}
            </Button>
          </div>
          {groupsError ? <Alert style={{ marginTop: 12 }} type="error" showIcon title={t('nodeReuseGroupsUnavailable')}
            action={<Button size="small" icon={<ReloadOutlined />} onClick={() => { void loadGroups(); }}>{t('refresh')}</Button>} /> : null}
          {!groupsError && eligibleGroups.length === 0 ? (
            <Typography.Text type="secondary">{t('nodeReuseNoEligibleGroups')}</Typography.Text>
          ) : null}
          {adding ? (
            <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--ant-color-border-secondary)' }}>
              <Space wrap>
                <Select aria-label={t('nodeReuseChooseGroup')} placeholder={t('nodeReuseChooseGroup')}
                  style={{ minWidth: 200, maxWidth: '100%' }} value={selectedGroupId}
                  options={eligibleGroups.map((group) => ({ value: group.id, label: group.name }))}
                  onChange={(value) => {
                    previewRequestId.current += 1;
                    setChecking(false);
                    setSelectedGroupId(value);
                    setPreview(null);
                    setPreviewForGroupId(null);
                    setPreviewError(null);
                  }} />
                <Button icon={<SafetyCertificateOutlined />} onClick={() => { void runPreflight(); }}
                  disabled={selectedGroupId === null} loading={checking}>{t('nodeReuseCheck')}</Button>
              </Space>
              {previewError ? <Alert style={{ marginTop: 12 }} type="error" showIcon title={previewError}
                description={t('nodeReuseNoChangeNext')} /> : null}
              {preview ? (
                <div style={{ marginTop: 12 }}>
                  <Alert type={preview.conflicts.length ? 'error' : 'success'} showIcon
                    title={preview.conflicts.length ? t('nodeReuseCheckBlocked') : t('nodeReuseCheckPassed')}
                    description={<>
                      <div>{t('nodeReuseImpact').replace('{groups}', String(preview.source_group_ids.length)).replace('{rules}', String(preview.sources.reduce((total, source) => total + source.rule_ids.length, 0)))}</div>
                      {preview.conflicts.map((conflict, index) => <div key={`${conflict.kind}-${index}`}>{conflictText(conflict, preview)}</div>)}
                      {preview.conflicts.length ? <div>{t('nodeReuseNoChangeNext')}</div> : null}
                    </>} />
                  <Space style={{ marginTop: 12 }}>
                    <Button type="primary" onClick={() => { void create(); }} loading={saving}
                      disabled={previewForGroupId !== selectedGroupId || !preview.known_runtime_prerequisites_satisfied || preview.conflicts.length > 0}>{t('nodeReuseConfirm')}</Button>
                    <Button onClick={() => {
                      previewRequestId.current += 1;
                      setAdding(false);
                      setSelectedGroupId(null);
                      setPreview(null);
                      setPreviewForGroupId(null);
                    }}>{t('cancel')}</Button>
                  </Space>
                </div>
              ) : null}
            </div>
          ) : null}
          <details style={{ marginTop: 16 }}>
            <summary>{t('nodeReuseAdvanced')}</summary>
            <div className="rp-mono" style={{ overflowWrap: 'anywhere' }}>
              {t('nodeReuseExpectedRevision')}: {runtime.expected_revision ?? '-'}<br />
              {t('nodeReuseExpectedFingerprint')}: {runtime.expected_fingerprint ?? '-'}
            </div>
          </details>
        </>
      ) : null}
    </section>
  );
}
