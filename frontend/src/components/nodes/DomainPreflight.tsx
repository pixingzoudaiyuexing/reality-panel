import { Alert, Button, Space, Typography } from 'antd';
import { useRef, useState } from 'react';
import api from '../../api/client';
import type { ApiEnvelope } from '../../api/types';

export type DomainPreflightResult = {
  fqdn: string;
  category: 'ABSENT' | 'PANEL_COMPATIBLE_A' | 'EXTERNAL_A' | 'CNAME' | 'UNMANAGED_ZONE' | 'UNCONFIGURED' | 'PROVIDER_READ_FAILURE';
  records: { record_type: string; values: string[]; line: string }[];
};
const messages: Record<DomainPreflightResult['category'], string> = {
  ABSENT: 'domainCheckAbsent', PANEL_COMPATIBLE_A: 'domainCheckOwned', EXTERNAL_A: 'domainCheckExternal',
  CNAME: 'domainCheckCname', UNMANAGED_ZONE: 'domainCheckUnmanaged', UNCONFIGURED: 'domainCheckUnconfigured',
  PROVIDER_READ_FAILURE: 'domainCheckFailed',
};

/** Advisory only; this component never affects Rule submission. Parent keys it
 * by SNI so changing the domain clears the result and pending response scope. */
export function DomainPreflight({ fqdn, t }: { fqdn: string; t: (key: string) => string }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DomainPreflightResult | null>(null);
  const request = useRef(0);
  const check = async () => {
    const current = ++request.current;
    setLoading(true);
    setResult(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<DomainPreflightResult>>('/admin/rules/domain-preflight', { fqdn });
      if (response.code !== 0 || !response.data || !messages[response.data.category]) throw new Error('preflight failed');
      if (request.current === current) setResult(response.data);
    } catch {
      if (request.current === current) setResult({ fqdn, category: 'PROVIDER_READ_FAILURE', records: [] });
    } finally {
      if (request.current === current) setLoading(false);
    }
  };
  const type = result?.category === 'PROVIDER_READ_FAILURE' ? 'error'
    : result?.category === 'ABSENT' || result?.category === 'PANEL_COMPATIBLE_A' ? 'info' : 'warning';
  return (
    <Space orientation="vertical" style={{ width: '100%', marginBottom: 16 }}>
      <Button size="small" disabled={!fqdn.trim()} loading={loading} onClick={() => { void check(); }}>{t('domainCheck')}</Button>
      {result && <Alert type={type} showIcon title={t(messages[result.category])} description={
        <div style={{ overflowWrap: 'anywhere' }}>
          {result.records.map((record, index) => <Typography.Text key={index} style={{ display: 'block' }}>
            {record.record_type}: {record.values.join(', ')} ({record.line})
          </Typography.Text>)}
          <Typography.Text type="secondary">{t('domainCheckReadonly')}</Typography.Text>
        </div>
      } />}
    </Space>
  );
}
