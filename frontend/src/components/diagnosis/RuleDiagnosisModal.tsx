import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, Button, Modal, Space, Spin, Table, Tag, Tooltip, Typography, message } from 'antd';
import { ReloadOutlined, ToolOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type {
  ApiEnvelope,
  DiagnoseResponse,
  DiagnoseTargetResult,
  ForwardRule,
  NodeDiagnoseStatus,
  ReapplyNodeStatus,
  ReapplyResponse,
  RealityCheck,
  RealityDiagnosis,
} from '../../api/types';
import { isRealityRule } from '../../utils/realityRuleStatus';
import type { Tfn } from '../nodes/types';
import {
  aggregateCheckDisplayStatuses,
  aggregateNodeBackends,
  aggregateNodeChecks,
  aggregateNodeListeners,
  deriveDiagnosisConclusion,
  diagnosisDisplayStatus,
  nodeBackendDisplayStatus,
  nodeDiagnosisIssues,
  nodeListenerDisplayStatus,
  primaryControlIssue,
  type DiagnosisCheckKey,
  type DiagnosisConclusionLevel,
  type DiagnosisDisplayStatus,
} from './summary';

const { Text, Title } = Typography;

interface Props {
  rule: ForwardRule | null;
  open: boolean;
  onClose: () => void;
  isAdmin: boolean;
  t: Tfn;
  nodeId?: string;
  nodeLabel?: string;
}

type CheckRowKey = 'dns' | 'listener' | 'certificate' | 'route' | 'backend' | 'client_path';

interface CheckRow {
  key: CheckRowKey;
  label: string;
  status: DiagnosisDisplayStatus;
  description: string;
  evidence?: ReactNode;
  help?: string;
}

interface NodeRow {
  key: string;
  node: NodeDiagnoseStatus;
  label: string;
  listener: DiagnosisDisplayStatus;
  backend: DiagnosisDisplayStatus;
  result: string;
}

function statusLabel(status: DiagnosisDisplayStatus, t: Tfn) {
  const keys: Record<DiagnosisDisplayStatus, Parameters<Tfn>[0]> = {
    normal: 'diagnosisNormal',
    abnormal: 'diagnosisAbnormal',
    waiting: 'diagnosisWaiting',
    not_tested: 'diagnosisNotTested',
    attention: 'diagnosisNeedsAttention',
    unknown: 'diagnosisStateUnknown',
    partial: 'diagnosisPartial',
  };
  return t(keys[status]);
}

function statusColor(status: DiagnosisDisplayStatus) {
  if (status === 'normal') return 'green';
  if (status === 'abnormal') return 'red';
  if (status === 'waiting' || status === 'attention' || status === 'partial') return 'orange';
  return 'default';
}

function StatusTag({ status, t, help }: { status: DiagnosisDisplayStatus; t: Tfn; help?: string }) {
  const tag = <Tag color={statusColor(status)}>{statusLabel(status, t)}</Tag>;
  return help ? <Tooltip title={help}>{tag}</Tooltip> : tag;
}

function conclusionLabel(level: DiagnosisConclusionLevel, t: Tfn) {
  if (level === 'healthy') return t('diagnosisHealthy');
  if (level === 'unavailable') return t('diagnosisUnavailable');
  return t('diagnosisPartial');
}

function reapplyNodeReason(node: ReapplyNodeStatus, t: Tfn) {
  if (node.state === 'unsupported') {
    return t('reapplyNodeUnsupported').replace('{version}', node.node_version || t('routeUnknown'));
  }
  if (node.state === 'control_channel_offline') return t('reapplyNodeOffline');
  if (node.state === 'timeout') return t('reapplyNodeTimeout');
  if (node.success) return t('reapplyNodeSuccess');
  if (node.error === 'no accepted configuration is available') return t('reapplyNodeNoAcceptedConfig');
  if (node.error === 'nginx_sni rule is not present in the accepted configuration') {
    return t('reapplyNodeRuleMissing');
  }
  if (node.error === 'nginx_sni disabled on this node') return t('reapplyNodeNginxDisabled');
  return node.error || t('reapplyFailed');
}

function formatElapsed(last: number | null, now: number, t: Tfn) {
  if (last === null) return '-';
  const seconds = Math.max(0, Math.floor((now - last) / 1000));
  if (seconds < 60) return `${seconds}${t('diagnosisSecondsAgo')}`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}${t('diagnosisMinutesAgo')}`;
  return new Date(last).toLocaleString();
}

function diagnosisRuleType(rule: ForwardRule, t: Tfn) {
  if (isRealityRule(rule)) return t('diagnosisRealityEntry');
  if (rule.protocol === 'tcp_udp') return t('tcpUdp');
  return rule.protocol?.toUpperCase() || '-';
}

function rawCheck(check?: RealityCheck | null) {
  if (!check) return '-';
  return `${check.state}${check.detail ? ` · ${check.detail}` : ''}`;
}

function EvidenceLine({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="rp-diagnosis-evidence-line">
      <Text type="secondary">{label}</Text>
      <div className="rp-diagnosis-evidence-value">{children}</div>
    </div>
  );
}

function blockedDescription(check: RealityCheck, t: Tfn) {
  if (check.detail === 'Public DNS is not ready') return t('diagnosisTableWaitingDns');
  if (check.detail === 'A usable certificate is not ready') return t('diagnosisTableWaitingCertificate');
  if (check.detail === 'DNSMgr is not ready') return t('diagnosisTableWaitingDnsmgr');
  return t('diagnosisTableWaitingPrerequisite');
}

function checkDescription(
  status: DiagnosisDisplayStatus,
  normal: string,
  abnormal: string,
  check: RealityCheck | undefined,
  t: Tfn,
) {
  if (status === 'normal') return normal;
  if (status === 'abnormal') return abnormal;
  if (status === 'waiting' && check) return blockedDescription(check, t);
  if (status === 'not_tested') return t('diagnosisTableNotTested');
  if (status === 'attention') return t('diagnosisTableNeedsAttention');
  if (status === 'partial') return t('diagnosisTablePartial');
  return t('diagnosisTableUnknown');
}

function DNSDetails({ rule, result, t }: { rule: ForwardRule; result: DiagnoseResponse; t: Tfn }) {
  const dependencies = result.dependencies;
  if (!dependencies) return <Text type="secondary">{t('diagnosisNoTechnicalEvidence')}</Text>;
  return (
    <div className="rp-diagnosis-evidence">
      {rule.sni ? <EvidenceLine label="FQDN"><Text className="rp-mono">{rule.sni}</Text></EvidenceLine> : null}
      <EvidenceLine label="DNSMgr"><Text className="rp-mono">{rawCheck(dependencies.dnsmgr)}</Text></EvidenceLine>
      <EvidenceLine label="dns_sync"><Text className="rp-mono">{rawCheck(dependencies.dns_sync)}</Text></EvidenceLine>
      {dependencies.blocking_chain.length > 0 ? (
        <EvidenceLine label="blocking_chain">
          <Space orientation="vertical" size={2}>
            {dependencies.blocking_chain.map((item, index) => (
              <Text className="rp-mono" key={`${item}-${index}`}>{index + 1}. {item}</Text>
            ))}
          </Space>
        </EvidenceLine>
      ) : null}
    </div>
  );
}

function ControlCheckDetails({ label, check }: { label: string; check?: RealityCheck }) {
  return (
    <div className="rp-diagnosis-evidence">
      <EvidenceLine label={label}><Text className="rp-mono">{rawCheck(check)}</Text></EvidenceLine>
    </div>
  );
}

function FullPathDetails({ nodes }: { nodes: NodeDiagnoseStatus[] }) {
  return (
    <div className="rp-diagnosis-evidence">
      {nodes.map((node) => (
        <EvidenceLine key={node.node_id} label={node.node_id}>
          <Text className="rp-mono">
            {node.status === 'result' && node.reality ? rawCheck(node.reality.vless_authentication) : node.status}
          </Text>
        </EvidenceLine>
      ))}
    </div>
  );
}

function RealityTechnicalEvidence({ diagnosis }: { diagnosis: RealityDiagnosis }) {
  return (
    <div className="rp-diagnosis-evidence">
      <EvidenceLine label="Config"><Text className="rp-mono">{rawCheck(diagnosis.config.check)}</Text></EvidenceLine>
      <EvidenceLine label="Config values">
        <Text className="rp-mono">SNI={diagnosis.config.sni ?? '-'} · port={diagnosis.config.listen_port} · proxy_protocol={String(diagnosis.config.send_proxy_protocol)} · targets={diagnosis.config.targets.join(', ') || '-'}</Text>
      </EvidenceLine>
      <EvidenceLine label="Convergence"><Text className="rp-mono">{rawCheck(diagnosis.convergence.check)}</Text></EvidenceLine>
      <EvidenceLine label="Revision"><Text className="rp-mono">desired={diagnosis.convergence.desired_config_revision} · active={diagnosis.convergence.active_config_revision}</Text></EvidenceLine>
      <EvidenceLine label="Fingerprint"><Text className="rp-mono">desired={diagnosis.convergence.desired_fingerprint} · active={diagnosis.convergence.active_fingerprint}</Text></EvidenceLine>
      <EvidenceLine label="Nginx"><Text className="rp-mono">{rawCheck(diagnosis.nginx.check)}</Text></EvidenceLine>
      <EvidenceLine label="Nginx values">
        <Text className="rp-mono">plan_contains_rule={String(diagnosis.nginx.plan_contains_rule)} · mapping_matches={String(diagnosis.nginx.mapping_matches)} · config_valid={String(diagnosis.nginx.config_valid)} · managed_file_matches={String(diagnosis.nginx.managed_file_matches)} · service_healthy={String(diagnosis.nginx.service_healthy)}</Text>
      </EvidenceLine>
      <EvidenceLine label="Nginx fingerprint"><Text className="rp-mono">expected={diagnosis.nginx.expected_fingerprint ?? '-'} · deployed={diagnosis.nginx.deployed_fingerprint ?? '-'}</Text></EvidenceLine>
      <EvidenceLine label="Runtime"><Text className="rp-mono">{rawCheck(diagnosis.runtime.check)} · :443={String(diagnosis.runtime.listen_443)} · :8443={String(diagnosis.runtime.listen_8443)}</Text></EvidenceLine>
      <EvidenceLine label="Backend">
        <Space orientation="vertical" size={2}>
          {diagnosis.backends.length > 0 ? diagnosis.backends.map((backend) => (
            <Text className="rp-mono" key={backend.address}>{backend.address} · {rawCheck(backend.check)}{backend.elapsed_ms != null ? ` · ${backend.elapsed_ms}ms` : ''}</Text>
          )) : <Text className="rp-mono">not_tested</Text>}
        </Space>
      </EvidenceLine>
      <EvidenceLine label="Certificate"><Text className="rp-mono">{rawCheck(diagnosis.certificate.check)}</Text></EvidenceLine>
      <EvidenceLine label="Certificate values">
        <Text className="rp-mono">status={diagnosis.certificate.certificate_status} · cert={diagnosis.certificate.cert_path ?? '-'} · key={diagnosis.certificate.key_path ?? '-'} · SAN={String(diagnosis.certificate.san_match)} · cert_key_match={String(diagnosis.certificate.cert_key_match)} · issuer={diagnosis.certificate.issuer ?? '-'} · valid_until={diagnosis.certificate.valid_until ?? '-'}</Text>
      </EvidenceLine>
      <EvidenceLine label="TLS"><Text className="rp-mono">{rawCheck(diagnosis.certificate.tls_handshake)}</Text></EvidenceLine>
      {diagnosis.certificate.renewal ? <EvidenceLine label="Renewal"><Text className="rp-mono">{rawCheck(diagnosis.certificate.renewal)}</Text></EvidenceLine> : null}
      <EvidenceLine label="Camouflage"><Text className="rp-mono">{rawCheck(diagnosis.camouflage.check)} · status={diagnosis.camouflage.site_status} · port={diagnosis.camouflage.tls_listener_port} · backend={diagnosis.camouflage.local_backend} · HTTP={diagnosis.camouflage.http_status ?? '-'}</Text></EvidenceLine>
      <EvidenceLine label="Fallback"><Text className="rp-mono">{rawCheck(diagnosis.fallback.check)} · HTTP={diagnosis.fallback.http_status ?? '-'} · authenticated_reality_path={String(diagnosis.fallback.authenticated_reality_path)}</Text></EvidenceLine>
      <EvidenceLine label="Client path"><Text className="rp-mono">{rawCheck(diagnosis.vless_authentication)}</Text></EvidenceLine>
    </div>
  );
}

function ProbeOutcome({ outcome }: { outcome: DiagnoseTargetResult['outcome'] }) {
  if (outcome === 'timeout') return <Text className="rp-mono">timeout</Text>;
  if ('reachable' in outcome) return <Text className="rp-mono">reachable · {outcome.reachable.elapsed_ms}ms</Text>;
  return <Text className="rp-mono">failed · {outcome.failed.error}</Text>;
}

function NodeTechnicalEvidence({ node }: { node: NodeDiagnoseStatus }) {
  if (node.status !== 'result') {
    return (
      <div className="rp-diagnosis-evidence">
        <EvidenceLine label="Node ID"><Text className="rp-mono">{node.node_id}</Text></EvidenceLine>
        <EvidenceLine label="status"><Text className="rp-mono">{node.status}</Text></EvidenceLine>
        {'node_version' in node ? <EvidenceLine label="version"><Text className="rp-mono">{node.node_version}</Text></EvidenceLine> : null}
      </div>
    );
  }
  return (
    <div className="rp-diagnosis-evidence">
      <EvidenceLine label="Node ID"><Text className="rp-mono">{node.node_id}</Text></EvidenceLine>
      <EvidenceLine label="Listener"><Text className="rp-mono">running={String(node.listener_running)} · port={node.listen_port} · protocol={node.protocol} · transport={node.transport}</Text></EvidenceLine>
      {node.reality ? <RealityTechnicalEvidence diagnosis={node.reality} /> : (
        <EvidenceLine label="Backend targets">
          {node.results.length > 0 ? (
            <Table<DiagnoseTargetResult>
              size="small"
              pagination={false}
              rowKey="address"
              dataSource={node.results}
              scroll={{ x: 460 }}
              columns={[
                { title: 'address', dataIndex: 'address', key: 'address', render: (value: string) => <Text className="rp-mono">{value}</Text> },
                { title: 'outcome', key: 'outcome', render: (_: unknown, row: DiagnoseTargetResult) => <ProbeOutcome outcome={row.outcome} /> },
              ]}
            />
          ) : <Text className="rp-mono">not_tested</Text>}
        </EvidenceLine>
      )}
    </div>
  );
}

function unavailableNodeReason(node: Exclude<NodeDiagnoseStatus, { status: 'result' }>, t: Tfn) {
  if (node.status === 'unsupported') return t('diagnosisUnsupportedNode');
  if (node.status === 'control_channel_offline') return t('diagnosisControlOffline');
  return t('diagnosisTimedOut');
}

function issueDescription(key: DiagnosisCheckKey, t: Tfn) {
  const keys: Partial<Record<DiagnosisCheckKey, Parameters<Tfn>[0]>> = {
    listener: 'diagnosisIssueListener',
    reality_service: 'diagnosisIssueRealityService',
    config: 'diagnosisIssueConfig',
    nginx: 'diagnosisIssueNginx',
    route: 'diagnosisIssueRoute',
    backend: 'diagnosisIssueBackend',
    certificate: 'diagnosisIssueCertificate',
    camouflage: 'diagnosisIssueCamouflage',
    client_path: 'diagnosisIssueClientPath',
    node_response: 'diagnosisIssueNodeResponse',
  };
  return t(keys[key] ?? 'diagnosisTableUnknown');
}

function nodeResult(node: NodeDiagnoseStatus, t: Tfn) {
  if (node.status !== 'result') return unavailableNodeReason(node, t);
  const issues = nodeDiagnosisIssues(node).filter((item) => {
    const status = diagnosisDisplayStatus(item.check);
    return status === 'abnormal' || status === 'attention' || status === 'unknown' || status === 'partial';
  });
  if (issues.length === 0) return t('diagnosisNodeNoIssue');
  const first = issues[0];
  const primary = issueDescription(first.causeKey ?? first.key, t);
  const more = issues.length - 1;
  return more > 0 ? `${primary} · ${t('diagnosisMoreIssues').replace('{count}', String(more))}` : primary;
}

function routeIssueDescription(nodes: NodeDiagnoseStatus[], fallback: string, t: Tfn) {
  const candidates = nodes.flatMap((node) => {
    if (node.status !== 'result' || !node.reality) return [];
    return [
      { key: 'nginx', check: node.reality.nginx.check },
      { key: 'config', check: node.reality.convergence.check },
      { key: 'route', check: node.reality.runtime.check },
      { key: 'config', check: node.reality.config.check },
      { key: 'camouflage', check: node.reality.camouflage.check },
      { key: 'fallback', check: node.reality.fallback.check },
    ];
  });
  const priority: Record<DiagnosisDisplayStatus, number> = {
    abnormal: 5, unknown: 4, waiting: 3, partial: 2, attention: 2, normal: 0, not_tested: 0,
  };
  const cause = candidates.reduce<(typeof candidates)[number] | null>((selected, candidate) => (
    !selected || priority[diagnosisDisplayStatus(candidate.check)] > priority[diagnosisDisplayStatus(selected.check)]
      ? candidate
      : selected
  ), null);
  if (!cause || priority[diagnosisDisplayStatus(cause.check)] === 0) return fallback;
  const display = diagnosisDisplayStatus(cause.check);
  if (cause.key === 'camouflage') {
    return t(display === 'attention' ? 'diagnosisIssueCamouflageWarning' : 'diagnosisIssueCamouflage');
  }
  if (cause.key === 'fallback') {
    return t(display === 'attention' ? 'diagnosisIssueFallbackWarning' : 'diagnosisIssueFallback');
  }
  return issueDescription(cause.key as DiagnosisCheckKey, t);
}

function buildCheckRows(rule: ForwardRule, result: DiagnoseResponse, t: Tfn): CheckRow[] {
  const realityRule = isRealityRule(rule);
  const listeners = aggregateNodeListeners(result.nodes);
  const backends = aggregateNodeBackends(result.nodes);
  const rows: CheckRow[] = [];

  if (realityRule) {
    const dependencies = result.dependencies;
    let dnsStatus: DiagnosisDisplayStatus = 'unknown';
    let dnsDescription = t('diagnosisTableDnsUnknown');
    if (dependencies) {
      const dnsmgr = diagnosisDisplayStatus(dependencies.dnsmgr);
      const dnsSync = diagnosisDisplayStatus(dependencies.dns_sync);
      if (dnsmgr !== 'normal') {
        dnsStatus = dnsmgr;
        dnsDescription = dnsmgr === 'abnormal'
          ? t('diagnosisTableDnsManagerFailed')
          : checkDescription(dnsmgr, t('diagnosisTableDnsNormal'), t('diagnosisTableDnsManagerFailed'), dependencies.dnsmgr, t);
      } else {
        dnsStatus = dnsSync;
        dnsDescription = checkDescription(dnsSync, t('diagnosisTableDnsNormal'), t('diagnosisTableDnsFailed'), dependencies.dns_sync, t);
      }
    }
    rows.push({
      key: 'dns', label: t('diagnosisDnsResolution'), status: dnsStatus,
      description: dnsDescription, evidence: <DNSDetails rule={rule} result={result} t={t} />,
    });
  }

  rows.push({
    key: 'listener', label: t('diagnosisListenerService'), status: listeners.status,
    description: listeners.status === 'normal'
      ? t('diagnosisTableListenerAllNormal').replace('{count}', String(listeners.total))
      : listeners.status === 'abnormal'
        ? t('diagnosisTableListenerAllFailed').replace('{count}', String(listeners.total))
        : listeners.status === 'partial'
          ? t('diagnosisTableListenerMixed').replace('{total}', String(listeners.total)).replace('{count}', String(listeners.abnormal))
        : listeners.status === 'attention'
          ? t('diagnosisTableListenerIncomplete')
          : listeners.status === 'not_tested'
            ? t('diagnosisTableListenerNotTested')
            : t('diagnosisTableUnknown'),
  });

  if (realityRule) {
    const certificate = result.dependencies?.certificate;
    const nodeCertificateChecks = result.nodes.flatMap((node) =>
      node.status === 'result' && node.reality
        ? [
          node.reality.certificate.check,
          node.reality.certificate.tls_handshake,
          ...(node.reality.certificate.renewal ? [node.reality.certificate.renewal] : []),
        ]
        : [],
    );
    const certificateStatus = aggregateCheckDisplayStatuses([
      ...(certificate ? [diagnosisDisplayStatus(certificate)] : []),
      ...nodeCertificateChecks.map(diagnosisDisplayStatus),
    ]);
    rows.push({
      key: 'certificate', label: t('diagnosisCertificate'), status: certificateStatus,
      description: checkDescription(certificateStatus, t('diagnosisTableCertificateNormal'), t('diagnosisTableCertificateFailed'), certificate, t),
      evidence: <ControlCheckDetails label="certificate" check={certificate} />,
    });

    const route = result.dependencies?.route;
    const nodeRouteChecks = result.nodes.flatMap((node) =>
      node.status === 'result' && node.reality
        ? [
          node.reality.config.check,
          node.reality.convergence.check,
          node.reality.nginx.check,
          node.reality.runtime.check,
          node.reality.camouflage.check,
          node.reality.fallback.check,
        ]
        : [],
    );
    const routeStatus = aggregateCheckDisplayStatuses([
      ...(route ? [diagnosisDisplayStatus(route)] : []),
      ...nodeRouteChecks.map(diagnosisDisplayStatus),
    ]);
    const routeFallback = checkDescription(routeStatus, t('diagnosisTableRouteNormal'), t('diagnosisTableRouteFailed'), route, t);
    rows.push({
      key: 'route', label: t('diagnosisRealityRoute'), status: routeStatus,
      description: routeStatus !== 'normal' && routeStatus !== 'not_tested'
        ? routeIssueDescription(result.nodes, routeFallback, t)
        : routeFallback,
      evidence: <ControlCheckDetails label="route" check={route} />,
    });
  }

  rows.push({
    key: 'backend', label: t('diagnosisBackendConnection'), status: backends.status,
    description: backends.status === 'normal'
      ? t('diagnosisTableBackendNormal').replace('{count}', String(backends.total))
      : backends.status === 'abnormal'
        ? t('diagnosisTableBackendFailed')
        : backends.status === 'partial'
          ? t('diagnosisTableBackendMixed')
          : backends.status === 'not_tested'
            ? t('diagnosisTableBackendNotTested')
            : backends.status === 'attention'
              ? t('diagnosisTableBackendAttention')
              : t('diagnosisTableUnknown'),
  });

  if (realityRule) {
    const pathChecks = result.nodes.flatMap((node) =>
      node.status === 'result' && node.reality ? [node.reality.vless_authentication] : [],
    );
    const pathStatus = aggregateNodeChecks(pathChecks);
    rows.push({
      key: 'client_path', label: t('diagnosisClientPath'), status: pathStatus,
      description: pathStatus === 'normal'
        ? t('diagnosisTableClientNormal')
        : pathStatus === 'not_tested'
          ? t('diagnosisTableClientNotTested')
          : pathStatus === 'abnormal'
            ? t('diagnosisTableClientFailed')
            : t('diagnosisTableUnknown'),
      help: pathStatus === 'not_tested' ? t('diagnosisClientPathExplanation') : undefined,
      evidence: <FullPathDetails nodes={result.nodes} />,
    });
  }
  return rows;
}

function buildNodeRows(nodes: NodeDiagnoseStatus[], t: Tfn): NodeRow[] {
  return nodes.map((node) => ({
    key: node.node_id,
    node,
    label: node.public_ip || t('diagnoseIpMissing'),
    listener: nodeListenerDisplayStatus(node),
    backend: nodeBackendDisplayStatus(node),
    result: nodeResult(node, t),
  }));
}

function summaryText(rows: CheckRow[], result: DiagnoseResponse, level: DiagnosisConclusionLevel, t: Tfn) {
  if (level === 'healthy') return t('diagnosisSummaryHealthy');
  const primary = result.dependencies?.blocking_chain.length ? primaryControlIssue(result.dependencies) : null;
  const primaryRow = primary
    ? rows.find((row) => primary.key === 'dnsmgr' || primary.key === 'dns_sync'
      ? row.key === 'dns'
      : primary.key === 'certificate'
        ? row.key === 'certificate'
        : row.key === 'route')
    : null;
  const listeners = aggregateNodeListeners(result.nodes);
  const independentListener = listeners.abnormal > 0 && primaryRow?.key !== 'listener'
    ? t('diagnosisSummaryAdditionalListener').replace('{count}', String(listeners.abnormal))
    : '';
  if (primaryRow) return `${primaryRow.description}${independentListener}`;
  const issueCount = rows.filter((row) => ['abnormal', 'partial', 'attention', 'unknown'].includes(row.status)).length;
  return issueCount > 0
    ? t('diagnosisSummaryGeneric').replace('{count}', String(issueCount))
    : t('diagnosisSummaryIncomplete');
}

export function RuleDiagnosisModal({ rule, open, onClose, isAdmin, t, nodeId, nodeLabel }: Props) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DiagnoseResponse | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [lastDiagnosedAt, setLastDiagnosedAt] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [repairing, setRepairing] = useState(false);
  const [repairResult, setRepairResult] = useState<ReapplyResponse | null>(null);
  const [repairError, setRepairError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const ruleId = rule?.id ?? null;

  const runDiagnosis = useCallback(async () => {
    if (ruleId === null || inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    setLoadFailed(false);
    try {
      const suffix = nodeId ? `?node_id=${encodeURIComponent(nodeId)}` : '';
      const response = await api.post<unknown, ApiEnvelope<DiagnoseResponse>>(`/rules/${ruleId}/diagnose${suffix}`);
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setResult(response.data);
      setExpandedKey(null);
      const completedAt = Date.now();
      setLastDiagnosedAt(completedAt);
      setNow(completedAt);
    } catch {
      setLoadFailed(true);
      message.error(t('diagnoseFailed'));
    } finally {
      inFlight.current = false;
      setLoading(false);
    }
  }, [nodeId, ruleId, t]);

  useEffect(() => {
    if (!open || ruleId === null) return;
    setResult(null);
    setLoadFailed(false);
    setLastDiagnosedAt(null);
    setExpandedKey(null);
    void runDiagnosis();
  }, [open, ruleId, nodeId, runDiagnosis]);

  useEffect(() => {
    if (!open) return;
    const timer = window.setInterval(() => setNow(Date.now()), 10000);
    return () => window.clearInterval(timer);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    setRepairResult(null);
    setRepairError(null);
  }, [open, ruleId]);

  const runReapply = async () => {
    if (!rule || repairing || !isRealityRule(rule)) return;
    setRepairing(true);
    setRepairResult(null);
    setRepairError(null);
    try {
      const response = await api.post<unknown, ApiEnvelope<ReapplyResponse>>(`/rules/${rule.id}/reapply`, {});
      if (response.code !== 0 || !response.data) {
        setRepairError(response.message || t('reapplyFailed'));
        return;
      }
      setRepairResult(response.data);
    } catch {
      setRepairError(t('reapplyRequestFailed'));
    } finally {
      setRepairing(false);
    }
  };

  const conclusion = result ? deriveDiagnosisConclusion(result.nodes, result.dependencies) : null;
  const checkRows = result && rule ? buildCheckRows(rule, result, t) : [];
  const nodeRows = result ? buildNodeRows(result.nodes, t) : [];
  const title = rule ? `${t('diagnoseTitle')} · ${nodeLabel ?? rule.name}` : t('diagnoseTitle');
  const repairAllSucceeded = !!repairResult
    && repairResult.nodes.length > 0
    && repairResult.applied === repairResult.nodes.length;

  const toggleEvidence = (key: string) => setExpandedKey((current) => current === key ? null : key);
  const actionButton = (key: string, hasEvidence: boolean) => hasEvidence ? (
    <Button type="link" size="small" onClick={() => toggleEvidence(key)}>
      {expandedKey === key ? t('diagnosisHideDetails') : t('diagnosisViewDetails')}
    </Button>
  ) : null;

  return (
    <Modal
      title={title}
      open={open}
      onCancel={onClose}
      width={800}
      className="rp-diagnosis-modal"
      footer={<Button onClick={onClose}>{t('close')}</Button>}
    >
      <div className="rp-diagnosis-toolbar">
        <Button icon={<ReloadOutlined />} loading={loading} disabled={loading} onClick={() => void runDiagnosis()}>{t('diagnosisRefresh')}</Button>
      </div>
      {loading && !result ? <div className="rp-diagnosis-loading"><Spin description={t('diagnoseRunning')} /></div> : null}
      {loadFailed ? (
        <Alert
          className="rp-diagnosis-load-error"
          type="error"
          showIcon
          title={t('diagnosisLoadFailed')}
          description={t('diagnosisLoadFailedHint')}
          action={<Button size="small" onClick={() => void runDiagnosis()}>{t('retry')}</Button>}
        />
      ) : null}
      {result && rule && conclusion ? (
        <div className="rp-diagnosis-content">
          <div className="rp-diagnosis-result" data-testid="diagnosis-conclusion">
            <Title level={4}>{t('diagnosisResult')}: {conclusionLabel(conclusion, t)}</Title>
            <Text>{summaryText(checkRows, result, conclusion, t)}</Text>
            <Text type="secondary" className="rp-diagnosis-context">
              {rule.listen_port} · {diagnosisRuleType(rule, t)} · {formatElapsed(lastDiagnosedAt, now, t)}
            </Text>
          </div>

          <section data-testid="diagnosis-check-table">
            <Title level={5}>{t('diagnosisCheckResults')}</Title>
            <Table<CheckRow>
              className="rp-diagnosis-table rp-diagnosis-check-table"
              size="small"
              pagination={false}
              rowKey={(row) => `check:${row.key}`}
              dataSource={checkRows}
              columns={[
                { title: t('diagnosisCheckItem'), dataIndex: 'label', key: 'label', width: 145, render: (value: string) => <Text strong>{value}</Text> },
                { title: t('status'), dataIndex: 'status', key: 'status', width: 100, render: (status: DiagnosisDisplayStatus, row) => <StatusTag status={status} t={t} help={row.help} /> },
                { title: t('diagnosisResultDescription'), dataIndex: 'description', key: 'description' },
                { title: t('action'), key: 'action', width: 72, render: (_: unknown, row) => actionButton(`check:${row.key}`, !!row.evidence) },
              ]}
              expandable={{
                showExpandColumn: false,
                expandedRowKeys: expandedKey?.startsWith('check:') ? [expandedKey] : [],
                expandedRowRender: (row) => expandedKey === `check:${row.key}` ? row.evidence ?? null : null,
                rowExpandable: (row) => !!row.evidence,
              }}
            />
          </section>

          <section data-testid="diagnosis-node-table">
            <Title level={5}>{t('diagnosisNodeChecks')}</Title>
            <Table<NodeRow>
              className="rp-diagnosis-table rp-diagnosis-node-table"
              size="small"
              pagination={false}
              rowKey={(row) => `node:${row.key}`}
              dataSource={nodeRows}
              columns={[
                {
                  title: t('diagnosisNode'), dataIndex: 'label', key: 'node', width: 175,
                  render: (value: string, row) => isAdmin
                    ? <Tooltip title={row.node.node_id}><Text className="rp-mono">{value}</Text></Tooltip>
                    : <Text className="rp-mono">{value}</Text>,
                },
                {
                  title: t('diagnosisListenerService'), dataIndex: 'listener', key: 'listener', width: 92,
                  render: (status: DiagnosisDisplayStatus) => (
                    <span className="rp-diagnosis-mobile-labelled" data-label={t('diagnosisListenerService')}>
                      <StatusTag status={status} t={t} />
                    </span>
                  ),
                },
                {
                  title: t('diagnosisBackend'), dataIndex: 'backend', key: 'backend', width: 92,
                  render: (status: DiagnosisDisplayStatus) => (
                    <span className="rp-diagnosis-mobile-labelled" data-label={t('diagnosisBackend')}>
                      <StatusTag status={status} t={t} />
                    </span>
                  ),
                },
                { title: t('diagnoseOutcome'), dataIndex: 'result', key: 'result' },
                { title: t('action'), key: 'action', width: 72, render: (_: unknown, row) => actionButton(`node:${row.key}`, true) },
              ]}
              expandable={{
                showExpandColumn: false,
                expandedRowKeys: expandedKey?.startsWith('node:') ? [expandedKey] : [],
                expandedRowRender: (row) => expandedKey === `node:${row.key}`
                  ? <NodeTechnicalEvidence node={row.node} />
                  : null,
              }}
            />
          </section>

          {isRealityRule(rule) ? (
            <section className="rp-diagnosis-repair" data-testid="diagnosis-repair-actions">
              <Title level={5}>{t('diagnosisRepairActions')}</Title>
              <Text type="secondary">{t('reapplyRepairDescription')}</Text>
              <div className="rp-diagnosis-repair-control">
                <Button icon={<ToolOutlined />} loading={repairing} disabled={repairing} onClick={() => void runReapply()}>
                  {t('reapply')}
                </Button>
              </div>
              {repairError ? <Alert type="error" showIcon title={repairError} /> : null}
              {repairResult ? (
                <Alert
                  type={repairAllSucceeded ? 'success' : repairResult.applied > 0 ? 'warning' : 'error'}
                  showIcon
                  title={repairAllSucceeded
                    ? t('reapplySuccess').replace('{count}', String(repairResult.applied))
                    : repairResult.nodes.length > 0
                      ? t('reapplyPartial').replace('{ok}', String(repairResult.applied)).replace('{fail}', String(repairResult.nodes.length - repairResult.applied))
                      : t('reapplyFailed')}
                  description={(
                    <Space orientation="vertical" size={2}>
                      {repairResult.nodes.map((node) => (
                        <Text key={node.node_id} type={node.state === 'result' && node.success ? 'success' : 'danger'}>
                          {node.public_ip || node.group_name}: {reapplyNodeReason(node, t)}
                        </Text>
                      ))}
                    </Space>
                  )}
                />
              ) : null}
            </section>
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}
