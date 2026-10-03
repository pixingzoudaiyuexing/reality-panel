import { Alert, Button, Descriptions, Input, InputNumber, Modal, Segmented, Space, Tabs, Tag, Typography, message } from 'antd';
import { CloudUploadOutlined, CopyOutlined, DeleteOutlined, PlusOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useEffect, useRef, useState } from 'react';
import api, { type ApiEnvelope } from '../api/client';
import type { ProvisioningCapabilities } from '../api/types';
import { useI18n } from '../i18n/context';
import type { Dict } from '../i18n/zh-CN';
import { copyText } from '../utils/clipboard';

const { Text } = Typography;
type Values = { group_id?: number; host: string; port: number; username: string; password: string };
type ExistingInstallation = { classification: 'CLEAN_HOST' | 'STALE_INACTIVE_RESIDUE' | 'MANAGED_EXISTING_NODE' | 'AMBIGUOUS_STATE'; old_node_id: string | null; version: string | null; profile: string | null; service_active: boolean; panel_present: boolean; online: boolean; credential_active: boolean; group_count: number; carrier_reference_count: number; reason: string | null; confirmation: string };
type SshProbe = { existing?: ExistingInstallation; fingerprint: string; os: string; architecture: string };
type DeployLog = { stage: string; message: string; at: string };
type Deployment = { id: string; group_id: number; host: string; stage: string; status: string; message: string; node_id?: string | null; profile: 'reality_camouflage'; lite_mode: boolean; capabilities?: ProvisioningCapabilities | null };
type RowState = 'WAITING' | 'TESTING' | 'PASSED' | 'FAILED' | 'DEPLOYING' | 'SUCCESS';
type SshRow = { overwriteConfirmed?: boolean; id: number; values: Values; state: RowState; probe: SshProbe | null; deployment: Deployment | null; logs: DeployLog[]; error: string | null };
type EnrollmentState = 'PENDING' | 'CLAIMED' | 'VERIFYING' | 'LOCAL_COMMITTED' | 'SUCCESS' | 'FAILED' | 'EXPIRED';
type Enrollment = { id: string; group_id: number; state: EnrollmentState; expires_at: string; session_expires_at?: string | null; node_id?: string | null; last_error_category?: string | null };
type CreatedEnrollment = { enrollment: Enrollment; enrollment_secret: string; launcher_command: string };

const newRow = (id: number, groupId?: number): SshRow => ({ id, values: { group_id: groupId, host: '', port: 22, username: 'root', password: '' }, state: 'WAITING', probe: null, deployment: null, logs: [], error: null });
const terminalEnrollment = (state: EnrollmentState) => ['SUCCESS', 'FAILED', 'EXPIRED'].includes(state);
const enrollmentStateLabel: Record<EnrollmentState, keyof Dict> = { PENDING: 'manualBootstrapStatePENDING', CLAIMED: 'manualBootstrapStateCLAIMED', VERIFYING: 'manualBootstrapStateVERIFYING', LOCAL_COMMITTED: 'manualBootstrapStateLOCAL_COMMITTED', SUCCESS: 'manualBootstrapStateSUCCESS', FAILED: 'manualBootstrapStateFAILED', EXPIRED: 'manualBootstrapStateEXPIRED' };
const rowColor: Record<RowState, string> = { WAITING: 'default', TESTING: 'processing', PASSED: 'success', FAILED: 'error', DEPLOYING: 'processing', SUCCESS: 'success' };

function errorText(error: unknown, fallback: string) {
  return (error as { response?: { data?: { message?: string } } })?.response?.data?.message || fallback;
}

export default function NodeBootstrap() {
  const { t } = useI18n();
  const nextId = useRef(2);
  const [rows, setRows] = useState<SshRow[]>([newRow(1)]);
  const [batchBusy, setBatchBusy] = useState(false);
  const [creatingEnrollment, setCreatingEnrollment] = useState(false);
  const [manualResult, setManualResult] = useState<CreatedEnrollment | null>(null);
  const [secretVisible, setSecretVisible] = useState(false);
  const [mode, setMode] = useState('ssh');
  const [liteMode, setLiteMode] = useState(false);


  useEffect(() => {
    if (!rows.some((row) => row.deployment && !['SUCCESS', 'FAILED'].includes(row.deployment.status))) return;
    const timer = window.setInterval(async () => {
      const active = rows.filter((row) => row.deployment && !['SUCCESS', 'FAILED'].includes(row.deployment.status));
      const updates = await Promise.all(active.map(async (row) => {
        try {
          const id = row.deployment!.id;
          const [status, logs] = await Promise.all([
            api.get<unknown, ApiEnvelope<Deployment>>(`/admin/node-deployments/${id}`),
            api.get<unknown, ApiEnvelope<DeployLog[]>>(`/admin/node-deployments/${id}/logs`),
          ]);
          return { id: row.id, deployment: status.data ?? row.deployment, logs: logs.data ?? row.logs };
        } catch { return null; }
      }));
      setRows((current) => current.map((row) => {
        const update = updates.find((item) => item?.id === row.id);
        if (!update) return row;
        return { ...row, deployment: update.deployment, logs: update.logs, state: update.deployment.status === 'SUCCESS' ? 'SUCCESS' : update.deployment.status === 'FAILED' ? 'FAILED' : 'DEPLOYING', error: update.deployment.status === 'FAILED' ? update.deployment.message : row.error };
      }));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [rows]);

  useEffect(() => {
    const enrollment = manualResult?.enrollment;
    if (!enrollment || terminalEnrollment(enrollment.state)) return;
    const timer = window.setInterval(async () => {
      try {
        const response = await api.get<unknown, ApiEnvelope<Enrollment>>(`/admin/node-enrollments/${enrollment.id}`);
        if (response.data) setManualResult((current) => current ? { ...current, enrollment: response.data! } : current);
      } catch { window.clearInterval(timer); }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [manualResult]);

  const updateRow = (id: number, patch: Partial<Values>) => setRows((current) => current.map((row) => row.id === id ? { ...row, values: { ...row.values, ...patch }, state: 'WAITING', probe: null, deployment: null, logs: [], error: null, overwriteConfirmed: false } : row));
  const rowValid = (row: SshRow) => Boolean(row.values.host.trim() && row.values.username.trim() && row.values.password && row.values.port >= 1 && row.values.port <= 65535);
  const rowsLocked = batchBusy || rows.some((row) => row.state === 'DEPLOYING');

  const testAll = async () => {
    if (!rows.every(rowValid)) { message.error(t('nodeBootstrapRowsIncomplete')); return; }
    setBatchBusy(true);
    setRows((current) => current.map((row) => ({ ...row, state: 'TESTING', probe: null, error: null, overwriteConfirmed: false })));
    const results = await Promise.all(rows.map(async (row) => {
      try {
        const response = await api.post<unknown, ApiEnvelope<SshProbe>>('/admin/node-deployments/fingerprint', { ...row.values, lite_mode: liteMode });
        if (!response.data) throw new Error(response.message);
        return { id: row.id, probe: response.data, error: null };
      } catch (error) { return { id: row.id, probe: null, error: errorText(error, t('nodeBootstrapSshFailed')) }; }
    }));
    setRows((current) => current.map((row) => {
      const result = results.find((item) => item.id === row.id);
      if (!result) return row;
      return { ...row, probe: result.probe, state: result.probe && result.probe.existing?.classification !== 'AMBIGUOUS_STATE' ? 'PASSED' : 'FAILED', error: result.error };
    }));
    setBatchBusy(false);
  };

  const canDeploy = (row: SshRow) => row.state === 'PASSED' && row.probe && (row.probe.existing?.classification === undefined || row.probe.existing.classification === 'CLEAN_HOST' || (row.probe.existing.classification !== 'AMBIGUOUS_STATE' && row.overwriteConfirmed));
  const confirmOverwrite = (row: SshRow) => {
    const old = row.probe?.existing;
    if (!old || !['STALE_INACTIVE_RESIDUE', 'MANAGED_EXISTING_NODE'].includes(old.classification)) return;
    Modal.confirm({
      title: t(old.classification === 'STALE_INACTIVE_RESIDUE' ? 'overwriteStaleTitle' : 'overwriteExistingTitle'),
      content: <Space orientation="vertical" style={{ width: '100%' }}>
        <Text code style={{ overflowWrap: 'anywhere' }}>{old.old_node_id}</Text>
        <Text>{t('overwriteRetirementWarning')}</Text>
        <Text strong>{old.profile ?? '-'} → {liteMode ? 'Lite' : 'Standard'}</Text>
        <Text>{old.group_count} {t('overwriteGroups')} · {old.carrier_reference_count} {t('overwriteCarrierRefs')}</Text>
        <Text type="secondary">{t('overwriteMembershipNotCopied')}</Text>
      </Space>,
      okText: t(old.classification === 'STALE_INACTIVE_RESIDUE' ? 'overwriteCleanInstall' : 'overwriteConfirm'),
      cancelText: t('cancel'), okButtonProps: { danger: true },
      onOk: () => setRows((current) => current.map((item) => item.id === row.id ? { ...item, overwriteConfirmed: true } : item)),
    });
  };

  const deployAll = async () => {
    if (!rows.every(canDeploy)) return;
    setBatchBusy(true);
    setRows((current) => current.map((row) => ({ ...row, state: 'DEPLOYING', error: null })));
    const results = await Promise.all(rows.map(async (row) => {
      try {
        const response = await api.post<unknown, ApiEnvelope<Deployment>>('/admin/node-deployments', { ...row.values, confirmed_fingerprint: row.probe!.fingerprint, profile: 'reality_camouflage', lite_mode: liteMode, ...(row.overwriteConfirmed ? { existing_confirmation: row.probe!.existing!.confirmation, overwrite_node_id: row.probe!.existing!.old_node_id } : {}) });
        if (!response.data) throw new Error(response.message);
        return { id: row.id, deployment: response.data, error: null };
      } catch (error) { return { id: row.id, deployment: null, error: errorText(error, t('nodeBootstrapStartFailed')) }; }
    }));
    setRows((current) => current.map((row) => {
      const result = results.find((item) => item.id === row.id);
      if (!result) return row;
      return { ...row, deployment: result.deployment, state: result.deployment ? 'DEPLOYING' : 'FAILED', error: result.error, values: { ...row.values, password: '' } };
    }));
    setBatchBusy(false);
  };

  const createEnrollment = async () => {
    setCreatingEnrollment(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<CreatedEnrollment>>('/admin/node-enrollments', { profile: 'reality_camouflage' });
      if (!response.data) throw new Error(response.message);
      setManualResult(response.data); setSecretVisible(true); message.success(t('manualBootstrapCreated'));
    } catch (error) { message.error(errorText(error, t('manualBootstrapCreateFailed'))); }
    finally { setCreatingEnrollment(false); }
  };
  const copyLauncher = async () => {
    if (!manualResult) return;
    const copied = await copyText(manualResult.launcher_command);
    message[copied ? 'success' : 'error'](t(copied ? 'manualBootstrapCommandCopied' : 'copyFailed'));
  };

  const sshContent = <>
    <Alert type="info" showIcon message={t('nodeBootstrapSshRecommended')} style={{ marginBottom: 16 }} />
    <Space orientation="vertical" size={4} style={{ marginBottom: 16 }}>
      <Text strong>{t('nodeBootstrapInstallMode')}</Text>
      <Segmented
        aria-label={t('nodeBootstrapInstallMode')}
        disabled={rowsLocked}
        value={liteMode ? 'lite' : 'standard'}
        options={[
          { value: 'standard', label: t('nodeBootstrapInstallStandard') },
          { value: 'lite', label: t('nodeBootstrapInstallLite') },
        ]}
        onChange={(value) => { setLiteMode(value === 'lite'); setRows((current) => current.map((row) => ({ ...row, overwriteConfirmed: false }))); }}
      />
      <Text type="secondary">{t(liteMode ? 'nodeBootstrapInstallLiteHint' : 'nodeBootstrapInstallStandardHint')}</Text>
    </Space>
    <div className="rp-ssh-batch" data-testid="ssh-batch">
      {rows.map((row, index) => <div className="rp-ssh-row" data-testid={`ssh-row-${row.id}`} key={row.id}>
        <Text type="secondary">#{index + 1}</Text>
        <Input disabled={rowsLocked} aria-label={`${t('nodeBootstrapHost')} ${index + 1}`} value={row.values.host} placeholder={t('nodeBootstrapHost')} onChange={(event) => updateRow(row.id, { host: event.target.value })} />
        <InputNumber disabled={rowsLocked} aria-label={`${t('nodeBootstrapPort')} ${index + 1}`} min={1} max={65535} value={row.values.port} onChange={(value) => updateRow(row.id, { port: value ?? 22 })} />
        <Input disabled={rowsLocked} aria-label={`${t('nodeBootstrapUser')} ${index + 1}`} value={row.values.username} onChange={(event) => updateRow(row.id, { username: event.target.value })} />
        <Input.Password disabled={rowsLocked} aria-label={`${t('nodeBootstrapPassword')} ${index + 1}`} value={row.values.password} autoComplete="new-password" onChange={(event) => updateRow(row.id, { password: event.target.value })} />
        <Space size={4}><Tag color={rowColor[row.state]}>{t(`nodeBootstrapRow${row.state}` as keyof Dict)}</Tag>{rows.length > 1 ? <Button disabled={rowsLocked} type="text" danger icon={<DeleteOutlined />} aria-label={`${t('delete')} ${index + 1}`} onClick={() => setRows((current) => current.filter((item) => item.id !== row.id))} /> : null}</Space>
        {row.error ? <Text type="danger" className="rp-ssh-row-message">{row.error}</Text> : row.deployment ? <Text className="rp-ssh-row-message">{row.deployment.message}</Text> : row.probe ? <Text type="secondary" className="rp-ssh-row-message">{row.probe.os} · {row.probe.architecture} · {row.probe.fingerprint}</Text> : null}
      </div>)}
    </div>
    {rows.map((row) => {
      const old = row.probe?.existing;
      if (!old || old.classification === 'CLEAN_HOST') return null;
      const ambiguous = old.classification === 'AMBIGUOUS_STATE';
      return <Alert key={row.id} style={{ marginTop: 12 }} type={ambiguous ? 'error' : 'warning'} showIcon
        title={t(ambiguous ? 'overwriteAmbiguousTitle' : old.classification === 'STALE_INACTIVE_RESIDUE' ? 'overwriteStaleTitle' : 'overwriteExistingTitle')}
        description={<Space orientation="vertical" style={{ width: '100%' }}>
          <Descriptions column={{ xs: 1, sm: 2 }} size="small" items={[
            { key: 'id', label: t('overwriteOldNode'), children: <Text code style={{ overflowWrap: 'anywhere' }}>{old.old_node_id}</Text> },
            { key: 'version', label: t('overwriteVersion'), children: old.version ?? '-' },
            { key: 'profile', label: t('overwriteProfile'), children: `${old.profile ?? '-'} → ${liteMode ? 'Lite' : 'Standard'}` },
            { key: 'status', label: t('status'), children: `${t(old.online ? 'online' : 'offline')} · ${t(old.service_active ? 'overwriteServiceActive' : 'overwriteServiceInactive')}` },
            { key: 'panel', label: t('overwritePanelIdentity'), children: `${t(old.panel_present ? 'overwritePresent' : 'overwriteAbsent')} · ${t(old.credential_active ? 'overwriteCredentialActive' : 'overwriteCredentialInactive')}` },
            { key: 'refs', label: t('overwriteRelations'), children: `${old.group_count} ${t('overwriteGroups')} · ${old.carrier_reference_count} ${t('overwriteCarrierRefs')}` },
          ]} />
          {old.reason ? <Text type="danger">{old.reason}</Text> : <Text>{t('overwriteRetirementWarning')}</Text>}
          {!ambiguous ? <Button danger disabled={rowsLocked || row.overwriteConfirmed} onClick={() => confirmOverwrite(row)}>{t(row.overwriteConfirmed ? 'overwriteConfirmed' : old.classification === 'STALE_INACTIVE_RESIDUE' ? 'overwriteCleanInstall' : 'overwriteConfirm')}</Button> : null}
        </Space>} />;
    })}
    <Space wrap style={{ marginTop: 12 }}>
      <Button disabled={rowsLocked} icon={<PlusOutlined />} onClick={() => setRows((current) => [...current, newRow(nextId.current++, current[0]?.values.group_id)])}>{t('nodeBootstrapAddServer')}</Button>
      <Button icon={<SafetyCertificateOutlined />} loading={batchBusy} onClick={() => void testAll()}>{t('nodeBootstrapTestConnection')}</Button>
      <Button type="primary" icon={<CloudUploadOutlined />} loading={batchBusy} disabled={!rows.every(canDeploy)} onClick={() => void deployAll()}>{t('nodeBootstrapDeploy')}</Button>
    </Space>
  </>;

  const enrollmentTag = (state: EnrollmentState) => <Tag color={state === 'SUCCESS' ? 'green' : state === 'FAILED' || state === 'EXPIRED' ? 'red' : state === 'LOCAL_COMMITTED' ? 'gold' : 'blue'}>{t(enrollmentStateLabel[state])}</Tag>;
  const manualContent = <>
    <Alert type="info" showIcon message={t('manualBootstrapDescription')} description={t('manualBootstrapNoSsh')} style={{ marginBottom: 16 }} />
    {!manualResult ? <Space orientation="vertical" style={{ width: '100%' }}><Button type="primary" icon={<CloudUploadOutlined />} loading={creatingEnrollment} onClick={() => void createEnrollment()}>{t('manualBootstrapCreate')}</Button></Space> : <section><Descriptions size="small" column={1} items={[{ key: 'state', label: t('status'), children: enrollmentTag(manualResult.enrollment.state) }, { key: 'expires', label: t('manualBootstrapExpiresAt'), children: manualResult.enrollment.expires_at }, ...(manualResult.enrollment.node_id ? [{ key: 'node', label: t('nodeStatus'), children: manualResult.enrollment.node_id }] : []), ...(manualResult.enrollment.last_error_category ? [{ key: 'error', label: t('manualBootstrapLastError'), children: manualResult.enrollment.last_error_category }] : [])]} />
      {manualResult.enrollment.state === 'LOCAL_COMMITTED' ? <Alert type="warning" showIcon message={t('manualBootstrapLocalCommitted')} style={{ marginTop: 12 }} /> : null}
      {secretVisible ? <Alert type="warning" showIcon message={t('manualBootstrapSecretOnceTitle')} description={<Space orientation="vertical" size={8} style={{ width: '100%' }}><Text>{t('manualBootstrapSecretOnceDescription')}</Text><Input.Password value={manualResult.enrollment_secret} readOnly visibilityToggle /><Button onClick={() => setSecretVisible(false)}>{t('manualBootstrapSecretAcknowledged')}</Button></Space>} style={{ marginTop: 12 }} /> : null}
      <div style={{ marginTop: 16 }}><Text strong>{t('manualBootstrapLauncherCommand')}</Text></div><Alert type="info" showIcon message={t('manualBootstrapLauncherHint')} style={{ margin: '8px 0' }} /><Input.TextArea value={manualResult.launcher_command} readOnly autoSize={{ minRows: 3, maxRows: 5 }} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 12 }} /><Button style={{ marginTop: 8 }} icon={<CopyOutlined />} onClick={() => void copyLauncher()}>{t('manualBootstrapCopyLauncher')}</Button>
    </section>}
  </>;

  return <Space orientation="vertical" size={16} style={{ width: '100%' }}><div className="rp-page-header"><h2 className="rp-page-title"><CloudUploadOutlined /> {t('nodeBootstrapTitle')}</h2></div><Tabs activeKey={mode} onChange={(next) => { setMode(next); if (next !== 'manual') setSecretVisible(false); }} items={[{ key: 'ssh', label: t('nodeBootstrapSshTab'), children: sshContent, forceRender: true }, { key: 'manual', label: t('manualBootstrapTab'), children: manualContent, forceRender: true }]} /></Space>;
}
