import { Alert, Button, Card, Form, Input, InputNumber, message, Result, Select, Space, Spin, Switch, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, DnsMgrConnectionTestResult, DnsMgrSettings, Plan, RegistrationSettings } from '../api/types';
import { useI18n } from '../i18n/context';

const { Text } = Typography;

/** v0.4.10 PR3 / v0.4.21 PR2: admin system settings page.
 *  Manages registration toggle, allowed registration plans (multi-select),
 *  and the default selected plan. */
export default function SystemSettings() {
  const { t } = useI18n();
  const [form] = Form.useForm();
  const [dnsForm] = Form.useForm();
  const [plans, setPlans] = useState<Plan[]>([]);
  const [dnsSettings, setDnsSettings] = useState<DnsMgrSettings | null>(null);
  const [dnsTestResult, setDnsTestResult] = useState<DnsMgrConnectionTestResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [dnsSaving, setDnsSaving] = useState(false);
  const [dnsTesting, setDnsTesting] = useState(false);

  const load = async () => {
    setLoading(true);
    setLoadFailed(false);
    try {
      const [settingsRes, plansRes, dnsRes] = await Promise.all([
        api.get<unknown, ApiEnvelope<RegistrationSettings>>('/admin/settings/registration'),
        api.get<unknown, ApiEnvelope<Plan[]>>('/admin/plans'),
        api.get<unknown, ApiEnvelope<DnsMgrSettings>>('/admin/settings/dnsmgr'),
      ]);
      if (settingsRes.data) {
        form.setFieldsValue({
          registration_enabled: settingsRes.data.registration_enabled,
          default_registration_plan_id: settingsRes.data.default_registration_plan_id,
          allowed_plan_ids: settingsRes.data.allowed_plan_ids,
        });
      }
      setPlans(plansRes.data || []);
      if (dnsRes.data) {
        setDnsSettings(dnsRes.data);
        dnsForm.setFieldsValue({
          enabled: dnsRes.data.enabled,
          base_url: dnsRes.data.base_url,
          uid: dnsRes.data.uid,
          api_key: '',
        });
      }
    } catch {
      setLoadFailed(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onSave = async () => {
    const values = await form.validateFields();

    // Client-side guard: allowed_plan_ids must not be empty.
    const allowed = (values.allowed_plan_ids as number[]) || [];
    if (allowed.length === 0) {
      message.error(t('allowedPlansRequired'));
      return;
    }

    // Client-side guard: default_plan_id must be in allowed_plan_ids.
    const defaultId = values.default_registration_plan_id as number;
    if (!allowed.includes(defaultId)) {
      message.error(t('defaultPlanNotAllowed'));
      return;
    }

    setSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<RegistrationSettings>>(
        '/admin/settings/registration',
        {
          enabled: values.registration_enabled,
          default_plan_id: defaultId,
          allowed_plan_ids: allowed,
        }
      );
      if (res.code !== 0) {
        message.error(res.message);
        return;
      }
      message.success(t('settingsSaved'));
    } catch {
      message.error(t('settingsSaveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const dnsPayload = async () => {
    const values = await dnsForm.validateFields();
    const replacement = String(values.api_key ?? '').trim();
    return {
      enabled: values.enabled === true,
      base_url: String(values.base_url ?? '').trim(),
      uid: Number(values.uid),
      ...(replacement ? { api_key: replacement } : {}),
    };
  };

  const onSaveDns = async () => {
    const payload = await dnsPayload();
    setDnsSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<DnsMgrSettings>>('/admin/settings/dnsmgr', payload);
      if (res.code !== 0 || !res.data) {
        message.error(res.message || t('settingsSaveFailed'));
        return;
      }
      setDnsSettings(res.data);
      dnsForm.setFieldValue('api_key', '');
      setDnsTestResult(null);
      message.success(t('settingsSaved'));
    } catch {
      message.error(t('settingsSaveFailed'));
    } finally {
      setDnsSaving(false);
    }
  };

  const onTestDns = async () => {
    const payload = await dnsPayload();
    setDnsTesting(true);
    setDnsTestResult(null);
    try {
      const res = await api.post<unknown, ApiEnvelope<DnsMgrConnectionTestResult>>(
        '/admin/settings/dnsmgr/test',
        { base_url: payload.base_url, uid: payload.uid, ...('api_key' in payload ? { api_key: payload.api_key } : {}) },
      );
      if (res.code !== 0 || !res.data) {
        message.error(res.message || t('dnsMgrConnectionTestFailed'));
        return;
      }
      setDnsTestResult(res.data);
    } catch {
      message.error(t('dnsMgrConnectionTestFailed'));
    } finally {
      setDnsTesting(false);
    }
  };

  // When allowed_plan_ids changes, clear default if it's no longer valid.
  const handleAllowedChange = (newAllowed: number[]) => {
    const currentDefault: number = form.getFieldValue('default_registration_plan_id');
    if (newAllowed.length > 0 && !newAllowed.includes(currentDefault)) {
      form.setFieldValue('default_registration_plan_id', newAllowed[0]);
    }
  };

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>;
  }
  if (loadFailed) {
    return (
      <Result
        status="warning"
        title={t('settingsLoadFailed')}
        extra={<Button type="primary" onClick={load}>{t('refresh')}</Button>}
      />
    );
  }

  const planOptions = plans.map((p) => ({ value: p.id, label: `${p.name} (${p.max_rules} ${t('rules')})` }));

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title={t('basicSettings')}
        extra={<Button type="primary" loading={saving} onClick={onSave}>{t('save')}</Button>}
      >
        <Form form={form} layout="vertical">
        <Form.Item
          name="registration_enabled"
          label={t('registrationEnabled')}
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>

        <Form.Item
          name="allowed_plan_ids"
          label={t('allowedPlans')}
          extra={t('allowedPlansHint')}
          rules={[{ required: true, message: t('allowedPlansRequired') }]}
        >
          <Select
            mode="multiple"
            options={planOptions}
            onChange={handleAllowedChange}
            placeholder={t('allowedPlans')}
          />
        </Form.Item>

        <Form.Item noStyle shouldUpdate={(prev, cur) => prev.allowed_plan_ids !== cur.allowed_plan_ids}>
          {({ getFieldValue }) => {
            const allowedIds: number[] = getFieldValue('allowed_plan_ids') || [];
            const defaultOptions = planOptions.filter(o => allowedIds.includes(o.value));
            return (
              <Form.Item
                name="default_registration_plan_id"
                label={t('defaultPlan')}
                rules={[{ required: true, message: t('defaultPlanRequired') }]}
                extra={allowedIds.length === 0 ? t('allowedPlansRequired') : undefined}
              >
                <Select
                  options={defaultOptions}
                  placeholder={t('selectPlan')}
                  disabled={allowedIds.length === 0}
                />
              </Form.Item>
            );
          }}
        </Form.Item>

        <Text type="secondary" style={{ fontSize: 12 }}>
          {t('registrationSettingsHint')}
        </Text>
        </Form>
      </Card>

      <Card
        title={t('dnsMgrSettings')}
        extra={<Button type="primary" loading={dnsSaving} onClick={onSaveDns}>{t('save')}</Button>}
      >
        <Form form={dnsForm} layout="vertical" style={{ maxWidth: 720 }}>
          <Space size={8} wrap style={{ marginBottom: 16 }}>
            <Text type="secondary">{t('configuredStatus')}</Text>
            <Tag color={dnsSettings?.configured ? 'green' : 'default'}>
              {dnsSettings?.configured ? t('configured') : t('notConfigured')}
            </Tag>
            <Tag color={dnsSettings?.has_api_key ? 'green' : 'default'}>
              {t('apiKey')}: {dnsSettings?.has_api_key ? t('configured') : t('notConfigured')}
            </Tag>
          </Space>
          <Form.Item name="enabled" label={t('enabled')} valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="base_url" label={t('baseUrl')} rules={[{ required: true }]}>
            <Input placeholder="http://127.0.0.1:8080" autoComplete="off" />
          </Form.Item>
          <Form.Item name="uid" label="UID" rules={[{ required: true }]}>
            <InputNumber min={1} precision={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="api_key" label={t('apiKeyReplacement')} extra={t('apiKeyBlankPreserves')}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button loading={dnsTesting} onClick={onTestDns}>{t('testConnection')}</Button>
          {dnsTestResult && (
            <Alert
              showIcon
              type={dnsTestResult.category === 'OK' ? 'success' : 'warning'}
              style={{ marginTop: 16 }}
              title={`${t('connectionTestResult')}: ${dnsTestResult.category}`}
              description={dnsTestResult.domain_count == null
                ? undefined
                : `${t('domainCount')}: ${dnsTestResult.domain_count}`}
            />
          )}
        </Form>
      </Card>
    </Space>
  );
}
