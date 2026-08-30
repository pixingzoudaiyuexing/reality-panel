import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Collapse, Modal, Space, Spin, Table, Tag, Tooltip, Typography, message } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type {
  ApiEnvelope,
  DiagnoseResponse,
  DiagnoseTargetResult,
  ForwardRule,
  NodeDiagnoseStatus,
  RealityCheck,
  RealityDiagnosis,
} from '../../api/types';
import { diagnosisStateDisplay } from '../../utils/realityRuleStatus';
import type { Tfn } from '../nodes/types';
import {
  backendSummary,
  deriveDiagnosisConclusion,
  deriveNodeDiagnosisSummary,
  type DiagnosisConclusionLevel,
} from './summary';

const { Text } = Typography;

interface Props {
  rule: ForwardRule | null;
  open: boolean;
  onClose: () => void;
  isAdmin: boolean;
  t: Tfn;
  nodeId?: string;
  nodeLabel?: string;
}

function checkTag(check: RealityCheck, t: Tfn) {
  const display = diagnosisStateDisplay(check.state, t);
  const tag = <Tag color={display.color}>{display.label}</Tag>;
  return check.detail ? <Tooltip title={check.detail}>{tag}</Tooltip> : tag;
}

function summaryState(check: RealityCheck, t: Tfn) {
  if (check.state === 'pass') return t('diagnosisNormal');
  if (check.state === 'not_tested') return t('diagnosisNotTested');
  if (check.state === 'fail') return t('diagnosisAbnormal');
  return t('diagnosisWarning');
}

function conclusionCopy(level: DiagnosisConclusionLevel, t: Tfn) {
  if (level === 'healthy') return {
    type: 'success' as const,
    label: t('diagnosisHealthy'),
    detail: t('diagnosisHealthyDetail'),
  };
  if (level === 'unavailable') return {
    type: 'error' as const,
    label: t('diagnosisUnavailable'),
    detail: t('diagnosisUnavailableDetail'),
  };
  return {
    type: 'warning' as const,
    label: t('diagnosisPartial'),
    detail: t('diagnosisPartialDetail'),
  };
}

function formatElapsed(last: number | null, now: number, t: Tfn) {
  if (last === null) return '';
  const seconds = Math.max(0, Math.floor((now - last) / 1000));
  if (seconds < 60) return `${seconds}${t('diagnosisSecondsAgo')}`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}${t('diagnosisMinutesAgo')}`;
  return new Date(last).toLocaleString();
}

function NodeSummary({ node, isAdmin, t }: { node: NodeDiagnoseStatus; isAdmin: boolean; t: Tfn }) {
  const summary = deriveNodeDiagnosisSummary(node);
  const label = `${node.group_name || '-'} · ${node.public_ip || t('diagnoseIpMissing')}`;
  const statusLabel = summary.level === 'normal'
    ? t('diagnosisNormal')
    : summary.level === 'critical' ? t('diagnosisAbnormal') : t('diagnosisWarning');
  const color = summary.level === 'normal' ? 'green' : summary.level === 'critical' ? 'red' : 'orange';

  if (node.status !== 'result') {
    const reason = node.status === 'unsupported'
      ? t('diagnosisUnsupportedNode')
      : node.status === 'control_channel_offline' ? t('diagnosisControlOffline') : t('diagnosisTimedOut');
    return (
      <div data-testid={`diagnosis-node-${node.node_id}`} style={{ padding: '10px 0', borderBottom: '1px solid var(--rp-border)' }}>
        <Space wrap><Text strong>{label}</Text><Tag color="orange">{t('diagnosisWarning')}</Tag></Space>
        <div><Text type="secondary">{reason}</Text></div>
      </div>
    );
  }

  const technical = node.reality
    ? <RealityTechnicalDetails diagnosis={node.reality} t={t} />
    : <TcpTechnicalDetails node={node} t={t} />;
  return (
    <div data-testid={`diagnosis-node-${node.node_id}`} style={{ padding: '10px 0', borderBottom: '1px solid var(--rp-border)' }}>
      <Space wrap>
        {isAdmin ? <Tooltip title={node.node_id}><Text strong>{label}</Text></Tooltip> : <Text strong>{label}</Text>}
        <Tag color={color}>{statusLabel}</Tag>
      </Space>
      {node.reality ? <RealitySummary diagnosis={node.reality} t={t} /> : <TcpSummary node={node} t={t} />}
      <Collapse
        ghost
        size="small"
        items={[{ key: 'details', label: t('diagnosisExpandDetails'), children: technical }]}
      />
    </div>
  );
}

function BackendLine({ reachable, total, slowestMs, t }: ReturnType<typeof backendSummary> & { t: Tfn }) {
  if (total === 0 || reachable === 0) return <Text>{t('diagnosisBackend')}: {t('diagnosisUnreachable')}</Text>;
  if (reachable < total) return <Text>{t('diagnosisBackend')}: {reachable}/{total} {t('diagnosisReachable')} · {total - reachable} {t('diagnosisIssueCount')}</Text>;
  return <Text>{t('diagnosisBackend')}: {reachable}/{total} {t('diagnosisReachable')}{slowestMs != null ? ` · ${t('diagnosisSlowest')} ${slowestMs} ms` : ''}</Text>;
}

function RealitySummary({ diagnosis, t }: { diagnosis: RealityDiagnosis; t: Tfn }) {
  const backend = backendSummary(diagnosis.backends.map((item) => ({ address: item.address, outcome: item.check.state === 'pass' ? { reachable: { elapsed_ms: item.elapsed_ms ?? 0 } } : { failed: { error: item.check.detail ?? item.check.state } } })));
  const routeState = [diagnosis.runtime.check, diagnosis.convergence.check].some((check) => check.state === 'fail')
    ? t('diagnosisAbnormal')
    : [diagnosis.runtime.check, diagnosis.convergence.check].every((check) => check.state === 'pass')
      ? t('diagnosisNormal') : t('diagnosisWarning');
  return (
    <Space orientation="vertical" size={2} style={{ display: 'flex', marginTop: 6 }}>
      <BackendLine {...backend} t={t} />
      <Text>{t('diagnosisCertificate')}: {diagnosis.certificate.remaining_days != null && diagnosis.certificate.check.state === 'pass' ? `${t('diagnosisRemaining')} ${diagnosis.certificate.remaining_days} ${t('days')}` : summaryState(diagnosis.certificate.check, t)}</Text>
      <Text>{t('diagnosisNginx')}: {summaryState(diagnosis.nginx.check, t)}</Text>
      <Text>{t('diagnosisRealityRoute')}: {routeState}</Text>
      <Text>{t('diagnosisCamouflage')}: {summaryState(diagnosis.camouflage.check, t)}</Text>
      <Text>{t('diagnosisClientPath')}: {summaryState(diagnosis.vless_authentication, t)}</Text>
      {diagnosis.vless_authentication.state === 'not_tested' ? <Text type="secondary">{t('diagnosisClientPathExplanation')}</Text> : null}
    </Space>
  );
}

function TcpSummary({ node, t }: { node: Extract<NodeDiagnoseStatus, { status: 'result' }>; t: Tfn }) {
  return (
    <Space orientation="vertical" size={2} style={{ display: 'flex', marginTop: 6 }}>
      <Text>{t('diagnosisListener')}: {node.listener_running ? t('diagnosisNormal') : t('diagnosisAbnormal')}</Text>
      <BackendLine {...backendSummary(node.results)} t={t} />
    </Space>
  );
}

function RealityTechnicalDetails({ diagnosis, t }: { diagnosis: RealityDiagnosis; t: Tfn }) {
  const status = (check: RealityCheck) => checkTag(check, t);
  return (
    <Space orientation="vertical" size={6} style={{ width: '100%' }}>
      <Text strong>{t('realityConfigLayer')}</Text>{status(diagnosis.config.check)}
      <Text type="secondary">SNI {diagnosis.config.sni ?? '-'} · :{diagnosis.config.listen_port} · PP {diagnosis.config.send_proxy_protocol ? 'ON' : 'OFF'}</Text>
      <Text strong>{t('realityConvergence')}</Text>{status(diagnosis.convergence.check)}
      <Text type="secondary">{t('realityDesiredSni')} {diagnosis.convergence.desired_sni ?? '-'} · {t('realityActiveSni')} {diagnosis.convergence.active_sni ?? '-'} · {t('realityRevision')} {diagnosis.convergence.desired_config_revision}/{diagnosis.convergence.active_config_revision}</Text>
      <Text className="rp-mono">{diagnosis.convergence.desired_fingerprint} / {diagnosis.convergence.active_fingerprint}</Text>
      <Text strong>{t('realityNginxLayer')}</Text>{status(diagnosis.nginx.check)}
      <Text type="secondary">plan_contains_rule={String(diagnosis.nginx.plan_contains_rule)} · mapping_matches={String(diagnosis.nginx.mapping_matches)} · config_valid={String(diagnosis.nginx.config_valid)} · managed_file_matches={String(diagnosis.nginx.managed_file_matches)} · service_healthy={String(diagnosis.nginx.service_healthy)}</Text>
      <Text type="secondary">expected_fingerprint={diagnosis.nginx.expected_fingerprint ?? '-'} · deployed_fingerprint={diagnosis.nginx.deployed_fingerprint ?? '-'}</Text>
      <Text strong>{t('realityRuntimeLayer')}</Text>{status(diagnosis.runtime.check)}
      <Text type="secondary">:443 {String(diagnosis.runtime.listen_443)} · :8443 {String(diagnosis.runtime.listen_8443)}</Text>
      <Text strong>{t('diagnosisBackend')}</Text>
      {diagnosis.backends.map((backend) => <Text key={backend.address} className="rp-mono">{backend.address} · {status(backend.check)}{backend.elapsed_ms != null ? ` · ${backend.elapsed_ms}ms` : ''}</Text>)}
      <Text strong>{t('diagnosisCertificate')}</Text>{status(diagnosis.certificate.check)}
      <Text type="secondary">{diagnosis.certificate.cert_path ?? '-'} · {diagnosis.certificate.key_path ?? '-'} · SAN={String(diagnosis.certificate.san_match)} · cert/key={String(diagnosis.certificate.cert_key_match)} · {diagnosis.certificate.issuer ?? '-'} · {diagnosis.certificate.valid_until ?? '-'}</Text>
      <Text strong>TLS</Text>{status(diagnosis.certificate.tls_handshake)}
      {diagnosis.certificate.renewal ? <><Text strong>{t('certificateRenewal')}</Text>{status(diagnosis.certificate.renewal)}</> : null}
      <Text strong>{t('diagnosisCamouflage')}</Text>{status(diagnosis.camouflage.check)}
      <Text type="secondary">:{diagnosis.camouflage.tls_listener_port} · {diagnosis.camouflage.local_backend} · HTTP {diagnosis.camouflage.http_status ?? '-'}</Text>
      <Text strong>{t('fallbackE2e')}</Text>{status(diagnosis.fallback.check)}
      <Text type="secondary">http_status={diagnosis.fallback.http_status ?? '-'} · authenticated_reality_path={String(diagnosis.fallback.authenticated_reality_path)}</Text>
      <Text strong>{t('diagnosisClientPath')}</Text>{status(diagnosis.vless_authentication)}
    </Space>
  );
}

function ProbeOutcome({ outcome, t }: { outcome: DiagnoseTargetResult['outcome']; t: Tfn }) {
  if (outcome === 'timeout') return <Tag color="orange">{t('diagnoseOutcomeTimeout')}</Tag>;
  if ('reachable' in outcome) return <Tag color="green">{t('diagnoseOutcomeReachable')} {outcome.reachable.elapsed_ms}ms</Tag>;
  return <Tag color="red">{t('diagnoseOutcomeFailed')}: {outcome.failed.error}</Tag>;
}

function TcpTechnicalDetails({ node, t }: { node: Extract<NodeDiagnoseStatus, { status: 'result' }>; t: Tfn }) {
  return (
    <Table<DiagnoseTargetResult>
      size="small"
      pagination={false}
      dataSource={node.results}
      rowKey="address"
      columns={[
        { title: t('diagnoseTarget'), dataIndex: 'address', key: 'address', render: (value: string) => <span className="rp-mono">{value}</span> },
        { title: t('diagnoseOutcome'), key: 'outcome', render: (_: unknown, row: DiagnoseTargetResult) => <ProbeOutcome outcome={row.outcome} t={t} /> },
      ]}
    />
  );
}

export function RuleDiagnosisModal({ rule, open, onClose, isAdmin, t, nodeId, nodeLabel }: Props) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DiagnoseResponse | null>(null);
  const [lastDiagnosedAt, setLastDiagnosedAt] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  const inFlight = useRef(false);
  const ruleId = rule?.id ?? null;

  const runDiagnosis = useCallback(async () => {
    if (ruleId === null || inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    try {
      const suffix = nodeId ? `?node_id=${encodeURIComponent(nodeId)}` : '';
      const response = await api.post<unknown, ApiEnvelope<DiagnoseResponse>>(`/rules/${ruleId}/diagnose${suffix}`);
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setResult(response.data);
      const completedAt = Date.now();
      setLastDiagnosedAt(completedAt);
      setNow(completedAt);
    } catch {
      message.error(t('diagnoseFailed'));
    } finally {
      inFlight.current = false;
      setLoading(false);
    }
  }, [nodeId, ruleId, t]);

  useEffect(() => {
    if (!open || ruleId === null) return;
    setResult(null);
    setLastDiagnosedAt(null);
    void runDiagnosis();
  }, [open, ruleId, nodeId, runDiagnosis]);

  useEffect(() => {
    if (!open) return;
    const timer = window.setInterval(() => setNow(Date.now()), 10000);
    return () => window.clearInterval(timer);
  }, [open]);

  const conclusion = result ? deriveDiagnosisConclusion(result.nodes, result.dependencies) : null;
  const conclusionView = conclusion ? conclusionCopy(conclusion, t) : null;
  const title = rule
    ? `${t('diagnoseTitle')} · ${rule.name} (#${rule.id})${nodeLabel ? ` · ${nodeLabel}` : ''}`
    : t('diagnoseTitle');

  return (
    <Modal
      title={title}
      open={open}
      onCancel={onClose}
      width={760}
      footer={<Button onClick={onClose}>{t('close')}</Button>}
    >
      <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        {lastDiagnosedAt ? <Text type="secondary">{t('diagnosisLastDiagnosed')}: {formatElapsed(lastDiagnosedAt, now, t)}</Text> : null}
        <Button icon={<ReloadOutlined />} loading={loading} disabled={loading} onClick={() => void runDiagnosis()}>{t('diagnosisRefresh')}</Button>
      </div>
      {loading && !result ? <div style={{ textAlign: 'center', padding: 32 }}><Spin tip={t('diagnoseRunning')} /></div> : null}
      {result && conclusionView ? (
        <>
          <Alert
            data-testid="diagnosis-conclusion"
            type={conclusionView.type}
            showIcon
            title={`${t('diagnosisResult')}: ${conclusionView.label}`}
            description={conclusionView.detail}
            style={{ marginBottom: 16 }}
          />
          {result.dependencies ? (
            <div data-testid="diagnosis-panel" style={{ marginBottom: 16 }}>
              <Typography.Title level={5}>{t('diagnosisPanelChecks')}</Typography.Title>
              <Space orientation="vertical" size={6}>
                <Space><Text strong>DNSMgr</Text>{checkTag(result.dependencies.dnsmgr, t)}</Space>
                <Space><Text strong>{t('diagnosisDnsResolution')}</Text>{checkTag(result.dependencies.dns_sync, t)}</Space>
              </Space>
            </div>
          ) : null}
          <div data-testid="diagnosis-nodes">
            <Typography.Title level={5}>{t('diagnosisNodeSummary')}</Typography.Title>
            {result.nodes.length === 0 ? <Text type="secondary">{t('diagnoseNoNodes')}</Text> : result.nodes.map((node) => (
              <NodeSummary key={node.node_id} node={node} isAdmin={isAdmin} t={t} />
            ))}
          </div>
        </>
      ) : null}
    </Modal>
  );
}
