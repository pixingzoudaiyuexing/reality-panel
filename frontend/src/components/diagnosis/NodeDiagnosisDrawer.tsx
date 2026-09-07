import { Alert, Button, Collapse, Descriptions, Drawer, Spin, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useState } from 'react';
import api from '../../api/client';
import type { ApiEnvelope, NodeDiagnosisCheck, NodeDiagnosisResponse } from '../../api/types';
import type { Tfn } from '../nodes/types';

const { Text } = Typography;

interface Props {
  target: { groupId: number; nodeId: string; label: string } | null;
  onClose: () => void;
  t: Tfn;
}

const checkNames: Record<string, string> = {
  heartbeat: '节点心跳', websocket: 'Panel 控制连接', identity: '节点身份', version: '节点版本',
  protocol: '配置协议', config_sync: '配置同步', runtime: '监听运行状态', camouflage: '伪装站总体状态',
  certificate_sync: '证书同步总体状态', resources: '系统资源', network: '节点网络',
  systemd: 'relay-node 服务', nginx: 'Nginx 进程',
};

function stateTag(check: NodeDiagnosisCheck, t: Tfn) {
  if (check.status === 'normal') return <Tag color="green">{t('diagnosisNormal')}</Tag>;
  if (check.status === 'not_observed') return <Tag>{t('diagnosisNotTested')}</Tag>;
  return <Tag color="red">{t('diagnosisAbnormal')}</Tag>;
}

export function NodeDiagnosisDrawer({ target, onClose, t }: Props) {
  const [result, setResult] = useState<NodeDiagnosisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const load = useCallback(async () => {
    if (!target) return;
    setLoading(true); setFailed(false);
    try {
      const response = await api.post<unknown, ApiEnvelope<NodeDiagnosisResponse>>(`/admin/nodes/${target.groupId}/${encodeURIComponent(target.nodeId)}/diagnose`, {});
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setResult(response.data);
    } catch { setFailed(true); }
    finally { setLoading(false); }
  }, [target]);
  useEffect(() => { if (target) void load(); else setResult(null); }, [load, target]);

  return <Drawer title={`${t('diagnose')} · ${target?.label ?? ''}`} open={target !== null} onClose={onClose} size={640} extra={<Button size="small" icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>{t('refresh')}</Button>}>
    {loading && !result ? <div style={{ textAlign: 'center', padding: 32 }}><Spin /></div> : null}
    {failed ? <Alert type="error" showIcon title={t('diagnosisLoadFailed')} action={<Button size="small" onClick={() => void load()}>{t('retry')}</Button>} /> : null}
    {result ? <>
      <Alert type={result.healthy ? 'success' : 'warning'} showIcon title={result.healthy ? t('nodeDiagnosisHealthy') : t('nodeDiagnosisAbnormal')} style={{ marginBottom: 12 }} />
      <Collapse items={(result.checks ?? []).map((check) => ({
        key: check.key,
        label: <span style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}><Text>{checkNames[check.key] ?? check.key}</Text>{stateTag(check, t)}</span>,
        children: <Descriptions size="small" column={1} bordered items={[
          { key: 'content', label: t('diagnosisCheckContent'), children: checkNames[check.key] ?? check.key },
          { key: 'expected', label: t('diagnosisExpectedResult'), children: check.expected },
          { key: 'actual', label: t('diagnosisCurrentResult'), children: check.actual },
          ...(check.impact ? [{ key: 'impact', label: t('diagnosisPossibleImpact'), children: <Text type="danger">{check.impact}</Text> }] : []),
          ...(check.technical ? [{ key: 'technical', label: t('diagnosisTechnicalInfo'), children: <Text code>{check.technical}</Text> }] : []),
        ]} />,
      }))} />
    </> : null}
  </Drawer>;
}
