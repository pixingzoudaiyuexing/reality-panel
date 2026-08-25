import { Alert, Button, Checkbox, Descriptions, Form, Input, InputNumber, List, Select, Space, Tabs, Tag, Typography, message } from 'antd';
import { CloudUploadOutlined, CopyOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api, { type ApiEnvelope } from '../api/client';
import type { DeviceGroup, ProvisioningCapabilities } from '../api/types';
import { useI18n } from '../i18n/context';
import type { Dict } from '../i18n/zh-CN';
import { copyText } from '../utils/clipboard';

const { Text } = Typography;

type Values = { group_id: number; host: string; port: number; username: string; password: string };
type SshProbe = { fingerprint: string; os: string; architecture: string };
type DeployLog = { stage: string; message: string; at: string };
type Deployment = { id: string; group_id: number; host: string; stage: string; status: string; message: string; node_id?: string | null; profile: 'reality_camouflage'; capabilities?: ProvisioningCapabilities | null };
type EnrollmentState = 'PENDING' | 'CLAIMED' | 'VERIFYING' | 'LOCAL_COMMITTED' | 'SUCCESS' | 'FAILED' | 'EXPIRED';
type Enrollment = { id: string; group_id: number; state: EnrollmentState; expires_at: string; session_expires_at?: string | null; node_id?: string | null; last_error_category?: string | null };
type CreatedEnrollment = { enrollment: Enrollment; enrollment_secret: string; launcher_command: string };

const terminalEnrollment = (state: EnrollmentState) => state === 'SUCCESS' || state === 'FAILED' || state === 'EXPIRED';
const enrollmentStateLabel: Record<EnrollmentState, keyof Dict> = {
  PENDING: 'manualBootstrapStatePENDING',
  CLAIMED: 'manualBootstrapStateCLAIMED',
  VERIFYING: 'manualBootstrapStateVERIFYING',
  LOCAL_COMMITTED: 'manualBootstrapStateLOCAL_COMMITTED',
  SUCCESS: 'manualBootstrapStateSUCCESS',
  FAILED: 'manualBootstrapStateFAILED',
  EXPIRED: 'manualBootstrapStateEXPIRED',
};

export default function NodeBootstrap() {
  const { t } = useI18n();
  const [searchParams] = useSearchParams();
  const [form] = Form.useForm<Values>();
  const [manualForm] = Form.useForm<{ group_id: number }>();
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [testing, setTesting] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [creatingEnrollment, setCreatingEnrollment] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [probe, setProbe] = useState<SshProbe | null>(null);
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [logs, setLogs] = useState<DeployLog[]>([]);
  const [manualResult, setManualResult] = useState<CreatedEnrollment | null>(null);
  const [secretVisible, setSecretVisible] = useState(false);
  const [mode, setMode] = useState('ssh');
  const groupId = Number(searchParams.get('group_id'));

  useEffect(() => {
    api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups')
      .then((response) => {
        const inbound = (response.data ?? []).filter((group) => group.group_type === 'in');
        setGroups(inbound);
        if (Number.isSafeInteger(groupId) && inbound.some((group) => group.id === groupId)) {
          form.setFieldValue('group_id', groupId);
          manualForm.setFieldValue('group_id', groupId);
        }
      })
      .catch(() => message.error(t('nodeBootstrapLoadFailed')));
  }, [form, groupId, manualForm, t]);

  useEffect(() => {
    if (!deployment || deployment.status === 'SUCCESS' || deployment.status === 'FAILED') return undefined;
    const timer = window.setInterval(async () => {
      try {
        const [status, taskLogs] = await Promise.all([
          api.get<unknown, ApiEnvelope<Deployment>>(`/admin/node-deployments/${deployment.id}`),
          api.get<unknown, ApiEnvelope<DeployLog[]>>(`/admin/node-deployments/${deployment.id}/logs`),
        ]);
        if (status.data) setDeployment(status.data);
        if (taskLogs.data) setLogs(taskLogs.data);
      } catch { window.clearInterval(timer); }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [deployment]);

  useEffect(() => {
    const enrollment = manualResult?.enrollment;
    if (!enrollment || terminalEnrollment(enrollment.state)) return undefined;
    const timer = window.setInterval(async () => {
      try {
        const response = await api.get<unknown, ApiEnvelope<Enrollment>>(`/admin/node-enrollments/${enrollment.id}`);
        if (response.data) setManualResult((current) => current ? { ...current, enrollment: response.data } : current);
      } catch { window.clearInterval(timer); }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [manualResult]);

  const testConnection = async () => {
    setTesting(true); setProbe(null); setConfirmed(false);
    try {
      const values = await form.validateFields(['host', 'port', 'username', 'password']);
      const response = await api.post<unknown, ApiEnvelope<SshProbe>>('/admin/node-deployments/fingerprint', values);
      if (!response.data) throw new Error(response.message);
      setProbe(response.data); message.success(t('nodeBootstrapSshPassed'));
    } catch (error) {
      const detail = error as { response?: { data?: { message?: string } } };
      message.error(detail.response?.data?.message || t('nodeBootstrapSshFailed'));
    } finally { setTesting(false); }
  };

  const deploy = async (values: Values) => {
    if (!probe || !confirmed) { message.error(t('nodeBootstrapConfirmFingerprint')); return; }
    setDeploying(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<Deployment>>('/admin/node-deployments', { ...values, confirmed_fingerprint: probe.fingerprint, profile: 'reality_camouflage' });
      if (!response.data) throw new Error(response.message);
      setDeployment(response.data); setLogs([]); form.setFieldValue('password', ''); setProbe(null); setConfirmed(false);
      message.success(t('nodeBootstrapStarted'));
    } catch (error) {
      const detail = error as { response?: { data?: { message?: string } } };
      message.error(detail.response?.data?.message || t('nodeBootstrapStartFailed'));
    } finally { setDeploying(false); }
  };

  const createEnrollment = async (values: { group_id: number }) => {
    setCreatingEnrollment(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<CreatedEnrollment>>('/admin/node-enrollments', { ...values, profile: 'reality_camouflage' });
      if (!response.data) throw new Error(response.message);
      setManualResult(response.data); setSecretVisible(true); message.success(t('manualBootstrapCreated'));
    } catch (error) {
      const detail = error as { response?: { data?: { message?: string } } };
      message.error(detail.response?.data?.message || t('manualBootstrapCreateFailed'));
    } finally { setCreatingEnrollment(false); }
  };

  const copyLauncher = async () => {
    if (!manualResult) return;
    if (await copyText(manualResult.launcher_command)) message.success(t('manualBootstrapCommandCopied'));
    else message.error(t('copyFailed'));
  };

  const enrollmentTag = (state: EnrollmentState) => {
    const color = state === 'SUCCESS' ? 'green' : state === 'FAILED' || state === 'EXPIRED' ? 'red' : state === 'LOCAL_COMMITTED' ? 'gold' : 'blue';
    return <Tag color={color}>{t(enrollmentStateLabel[state])}</Tag>;
  };

  const capabilityItems = deployment?.capabilities ? [
    { key: 'nginx_stream', label: t('nodeCapabilityNginxStream'), children: <Tag color={deployment.capabilities.nginx_stream ? 'green' : 'red'}>{deployment.capabilities.nginx_stream ? 'PASS' : 'FAIL'}</Tag> },
    { key: 'openlist', label: t('nodeCapabilityOpenList'), children: <Tag color={deployment.capabilities.openlist ? 'green' : 'red'}>{deployment.capabilities.openlist ? 'PASS' : 'FAIL'}</Tag> },
    { key: 'http01', label: t('nodeCapabilityHttp01'), children: <Tag color={deployment.capabilities.http01 ? 'green' : 'red'}>{deployment.capabilities.http01 ? 'PASS' : 'FAIL'}</Tag> },
    { key: 'certificate_lifecycle', label: t('nodeCapabilityCertificateLifecycle'), children: <Tag color={deployment.capabilities.certificate_lifecycle ? 'green' : 'red'}>{deployment.capabilities.certificate_lifecycle ? 'PASS' : 'FAIL'}</Tag> },
    { key: 'reality_camouflage', label: t('nodeCapabilityRealityCamouflage'), children: <Tag color={deployment.capabilities.reality_camouflage ? 'green' : 'red'}>{deployment.capabilities.reality_camouflage ? 'PASS' : 'FAIL'}</Tag> },
  ] : [];

  const sshContent = <>
    <Alert type="info" showIcon message={t('nodeBootstrapSshRecommended')} style={{ marginBottom: 16 }} />
    <Form name="ssh-bootstrap" form={form} layout="vertical" initialValues={{ port: 22, username: 'root' }} onFinish={deploy} onValuesChange={() => { setProbe(null); setConfirmed(false); }}>
      <Form.Item name="group_id" label={t('nodeBootstrapGroup')} rules={[{ required: true }]}><Select options={groups.map((group) => ({ value: group.id, label: group.name }))} /></Form.Item>
      <Form.Item name="host" label={t('nodeBootstrapHost')} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
      <Form.Item name="port" label={t('nodeBootstrapPort')} rules={[{ required: true }]}><InputNumber min={1} max={65535} style={{ width: '100%' }} /></Form.Item>
      <Form.Item name="username" label={t('nodeBootstrapUser')} rules={[{ required: true }]}><Input autoComplete="username" /></Form.Item>
      <Form.Item name="password" label={t('nodeBootstrapPassword')} rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
      <Space wrap><Button icon={<SafetyCertificateOutlined />} onClick={testConnection} loading={testing}>{t('nodeBootstrapTestConnection')}</Button><Button type="primary" htmlType="submit" icon={<CloudUploadOutlined />} loading={deploying} disabled={!probe || !confirmed}>{t('nodeBootstrapDeploy')}</Button></Space>
    </Form>
    {probe && <Alert type="success" showIcon style={{ marginTop: 16 }} message={t('nodeBootstrapFingerprintConfirmed')} description={<><Descriptions size="small" column={1} items={[
      { key: 'os', label: t('nodeBootstrapOs'), children: probe.os }, { key: 'arch', label: t('nodeBootstrapArch'), children: probe.architecture }, { key: 'fingerprint', label: t('nodeBootstrapFingerprint'), children: <code>{probe.fingerprint}</code> },
    ]} /><Checkbox checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}>{t('nodeBootstrapFingerprintConfirm')}</Checkbox></>} />}
    {deployment && <section style={{ marginTop: 16 }}><Space style={{ marginBottom: 8 }}><Tag color={deployment.status === 'SUCCESS' ? 'green' : deployment.status === 'FAILED' ? 'red' : 'blue'}>{deployment.stage}</Tag><span>{t('nodeBootstrapTask')}</span></Space><Alert type={deployment.status === 'FAILED' ? 'error' : deployment.status === 'SUCCESS' ? 'success' : 'info'} showIcon message={deployment.message} />{capabilityItems.length > 0 && <Descriptions size="small" column={{ xs: 1, sm: 2 }} style={{ marginTop: 12 }} items={capabilityItems} />}<List size="small" style={{ marginTop: 12 }} dataSource={logs} renderItem={(log) => <List.Item><Tag>{log.stage}</Tag>{log.message}</List.Item>} /></section>}
  </>;

  const manualContent = <>
    <Alert type="info" showIcon message={t('manualBootstrapDescription')} description={t('manualBootstrapNoSsh')} style={{ marginBottom: 16 }} />
    {!manualResult && <Form name="manual-bootstrap" form={manualForm} layout="vertical" onFinish={createEnrollment}><Form.Item name="group_id" label={t('nodeBootstrapGroup')} rules={[{ required: true }]}><Select options={groups.map((group) => ({ value: group.id, label: group.name }))} /></Form.Item><Button type="primary" htmlType="submit" icon={<CloudUploadOutlined />} loading={creatingEnrollment}>{t('manualBootstrapCreate')}</Button></Form>}
    {manualResult && <section><Descriptions size="small" column={1} items={[
      { key: 'state', label: t('status'), children: enrollmentTag(manualResult.enrollment.state) }, { key: 'expires', label: t('manualBootstrapExpiresAt'), children: manualResult.enrollment.expires_at },
      ...(manualResult.enrollment.node_id ? [{ key: 'node', label: t('nodeStatus'), children: manualResult.enrollment.node_id }] : []), ...(manualResult.enrollment.last_error_category ? [{ key: 'error', label: t('manualBootstrapLastError'), children: manualResult.enrollment.last_error_category }] : []),
    ]} />
      {manualResult.enrollment.state === 'LOCAL_COMMITTED' && <Alert type="warning" showIcon message={t('manualBootstrapLocalCommitted')} style={{ marginTop: 12 }} />}
      {secretVisible && <Alert type="warning" showIcon message={t('manualBootstrapSecretOnceTitle')} description={<Space direction="vertical" size={8} style={{ width: '100%' }}><Text>{t('manualBootstrapSecretOnceDescription')}</Text><Input.Password value={manualResult.enrollment_secret} readOnly visibilityToggle /><Button onClick={() => setSecretVisible(false)}>{t('manualBootstrapSecretAcknowledged')}</Button></Space>} style={{ marginTop: 12 }} />}
      <div style={{ marginTop: 16 }}><Text strong>{t('manualBootstrapLauncherCommand')}</Text></div><Alert type="info" showIcon message={t('manualBootstrapLauncherHint')} style={{ margin: '8px 0' }} /><Input.TextArea value={manualResult.launcher_command} readOnly autoSize={{ minRows: 3, maxRows: 5 }} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 12 }} /><Button style={{ marginTop: 8 }} icon={<CopyOutlined />} onClick={copyLauncher}>{t('manualBootstrapCopyLauncher')}</Button>
    </section>}
  </>;

  return <Space direction="vertical" size={16} style={{ width: '100%' }}><div className="rp-page-header"><h2 className="rp-page-title"><CloudUploadOutlined /> {t('nodeBootstrapTitle')}</h2></div><Tabs activeKey={mode} onChange={(next) => { setMode(next); if (next !== 'manual') setSecretVisible(false); }} items={[{ key: 'ssh', label: t('nodeBootstrapSshTab'), children: sshContent, forceRender: true }, { key: 'manual', label: t('manualBootstrapTab'), children: manualContent, forceRender: true }]} /></Space>;
}
