import { Alert, Button, Checkbox, Descriptions, Form, Input, InputNumber, List, Select, Space, Tag, message } from 'antd';
import { CloudUploadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useEffect, useState } from 'react';
import api, { type ApiEnvelope } from '../api/client';
import type { DeviceGroup, ProvisioningCapabilities } from '../api/types';
import { useI18n } from '../i18n/context';

type Values = { group_id: number; host: string; port: number; username: string; password: string };
type SshProbe = { fingerprint: string; os: string; architecture: string };
type DeployLog = { stage: string; message: string; at: string };
type Deployment = {
  id: string;
  group_id: number;
  host: string;
  stage: string;
  status: string;
  message: string;
  node_id?: string | null;
  profile: 'reality_camouflage';
  capabilities?: ProvisioningCapabilities | null;
};

export default function NodeBootstrap() {
  const { t } = useI18n();
  const [form] = Form.useForm<Values>();
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [testing, setTesting] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [probe, setProbe] = useState<SshProbe | null>(null);
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [logs, setLogs] = useState<DeployLog[]>([]);

  useEffect(() => {
    api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups')
      .then((response) => setGroups((response.data ?? []).filter((group) => group.group_type === 'in')))
      .catch(() => message.error(t('nodeBootstrapLoadFailed')));
  }, [t]);

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
      const response = await api.post<unknown, ApiEnvelope<Deployment>>('/admin/node-deployments', {
        ...values,
        confirmed_fingerprint: probe.fingerprint,
        profile: 'reality_camouflage',
      });
      if (!response.data) throw new Error(response.message);
      setDeployment(response.data); setLogs([]); form.setFieldValue('password', ''); setProbe(null); setConfirmed(false);
      message.success(t('nodeBootstrapStarted'));
    } catch (error) {
      const detail = error as { response?: { data?: { message?: string } } };
      message.error(detail.response?.data?.message || t('nodeBootstrapStartFailed'));
    } finally { setDeploying(false); }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="rp-page-header"><h2 className="rp-page-title"><CloudUploadOutlined /> {t('nodeBootstrapTitle')}</h2></div>
      <Form form={form} layout="vertical" initialValues={{ port: 22, username: 'root' }} onFinish={deploy} onValuesChange={() => { setProbe(null); setConfirmed(false); }}>
        <Form.Item name="group_id" label={t('nodeBootstrapGroup')} rules={[{ required: true }]}><Select options={groups.map((group) => ({ value: group.id, label: group.name }))} /></Form.Item>
        <Form.Item name="host" label={t('nodeBootstrapHost')} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="port" label={t('nodeBootstrapPort')} rules={[{ required: true }]}><InputNumber min={1} max={65535} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="username" label={t('nodeBootstrapUser')} rules={[{ required: true }]}><Input autoComplete="username" /></Form.Item>
        <Form.Item name="password" label={t('nodeBootstrapPassword')} rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Space wrap>
          <Button icon={<SafetyCertificateOutlined />} onClick={testConnection} loading={testing}>{t('nodeBootstrapTestConnection')}</Button>
          <Button type="primary" htmlType="submit" icon={<CloudUploadOutlined />} loading={deploying} disabled={!probe || !confirmed}>{t('nodeBootstrapDeploy')}</Button>
        </Space>
      </Form>
      {probe && <Alert type="success" showIcon message={t('nodeBootstrapFingerprintConfirmed')} description={<><Descriptions size="small" column={1} items={[
        { key: 'os', label: t('nodeBootstrapOs'), children: probe.os },
        { key: 'arch', label: t('nodeBootstrapArch'), children: probe.architecture },
        { key: 'fingerprint', label: t('nodeBootstrapFingerprint'), children: <code>{probe.fingerprint}</code> },
      ]} /><Checkbox checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}>{t('nodeBootstrapFingerprintConfirm')}</Checkbox></>} />}
      {deployment && <section>
        <Space style={{ marginBottom: 8 }}><Tag color={deployment.status === 'SUCCESS' ? 'green' : deployment.status === 'FAILED' ? 'red' : 'blue'}>{deployment.stage}</Tag><span>{t('nodeBootstrapTask')}</span></Space>
        <Alert type={deployment.status === 'FAILED' ? 'error' : deployment.status === 'SUCCESS' ? 'success' : 'info'} showIcon message={deployment.message} />
        {deployment.capabilities && <Descriptions size="small" column={{ xs: 1, sm: 2 }} style={{ marginTop: 12 }} items={[
          { key: 'nginx_stream', label: t('nodeCapabilityNginxStream'), children: <Tag color={deployment.capabilities.nginx_stream ? 'green' : 'red'}>{deployment.capabilities.nginx_stream ? 'PASS' : 'FAIL'}</Tag> },
          { key: 'openlist', label: t('nodeCapabilityOpenList'), children: <Tag color={deployment.capabilities.openlist ? 'green' : 'red'}>{deployment.capabilities.openlist ? 'PASS' : 'FAIL'}</Tag> },
          { key: 'http01', label: t('nodeCapabilityHttp01'), children: <Tag color={deployment.capabilities.http01 ? 'green' : 'red'}>{deployment.capabilities.http01 ? 'PASS' : 'FAIL'}</Tag> },
          { key: 'certificate_lifecycle', label: t('nodeCapabilityCertificateLifecycle'), children: <Tag color={deployment.capabilities.certificate_lifecycle ? 'green' : 'red'}>{deployment.capabilities.certificate_lifecycle ? 'PASS' : 'FAIL'}</Tag> },
          { key: 'reality_camouflage', label: t('nodeCapabilityRealityCamouflage'), children: <Tag color={deployment.capabilities.reality_camouflage ? 'green' : 'red'}>{deployment.capabilities.reality_camouflage ? 'PASS' : 'FAIL'}</Tag> },
        ]} />}
        <List size="small" style={{ marginTop: 12 }} dataSource={logs} renderItem={(log) => <List.Item><Tag>{log.stage}</Tag>{log.message}</List.Item>} />
      </section>}
    </Space>
  );
}
