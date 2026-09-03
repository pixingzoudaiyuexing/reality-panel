import type { DiagnoseTargetResult, NodeDiagnoseStatus, RealityCheck } from '../../api/types';

export type DiagnosisConclusionLevel = 'healthy' | 'partial' | 'unavailable';
export type NodeDiagnosisLevel = 'normal' | 'warning' | 'critical';

export interface NodeDiagnosisSummary {
  level: NodeDiagnosisLevel;
  incomplete: boolean;
}

export type DiagnosisCheckKey =
  | 'dns'
  | 'reality_service'
  | 'config'
  | 'nginx'
  | 'route'
  | 'certificate'
  | 'camouflage'
  | 'backend'
  | 'client_path'
  | 'listener'
  | 'node_response';

export interface DiagnosisCheckSummary {
  key: DiagnosisCheckKey;
  check: RealityCheck;
  causeKey?: DiagnosisCheckKey;
}

export type ControlCheckKey = 'dnsmgr' | 'dns_sync' | 'certificate' | 'route';

export interface ControlCheckSummary {
  key: ControlCheckKey;
  check: RealityCheck;
}

export type DiagnosisDisplayStatus =
  | 'normal'
  | 'abnormal'
  | 'waiting'
  | 'not_tested'
  | 'attention'
  | 'unknown'
  | 'partial';

export interface DiagnosisAggregate {
  status: DiagnosisDisplayStatus;
  total: number;
  normal: number;
  abnormal: number;
  notTested: number;
}

const isIssue = (check?: RealityCheck | null) =>
  !!check && ['warning', 'fail', 'blocked'].includes(check.state);
const isFail = (check?: RealityCheck | null) => check?.state === 'fail';

export function diagnosisDisplayStatus(check?: RealityCheck | null): DiagnosisDisplayStatus {
  if (!check || check.state === 'not_tested') return 'not_tested';
  if (check.state === 'pass') return 'normal';
  if (check.state === 'fail') return 'abnormal';
  if (check.state === 'blocked') return 'waiting';
  if (check.state === 'warning') return 'attention';
  return 'unknown';
}

export function aggregateDiagnosisStatuses(statuses: DiagnosisDisplayStatus[]): DiagnosisAggregate {
  const total = statuses.length;
  const normal = statuses.filter((status) => status === 'normal').length;
  const abnormal = statuses.filter((status) => status === 'abnormal').length;
  const notTested = statuses.filter((status) => status === 'not_tested').length;
  const partial = statuses.filter((status) => status === 'partial').length;
  const attention = statuses.filter((status) => status === 'attention').length;
  const unknown = statuses.filter((status) => status === 'unknown').length;
  const waiting = statuses.filter((status) => status === 'waiting').length;

  let status: DiagnosisDisplayStatus;
  if (total === 0 || notTested === total) status = 'not_tested';
  else if (abnormal === total) status = 'abnormal';
  else if (abnormal > 0 || partial > 0) status = 'partial';
  else if (unknown > 0) status = 'unknown';
  else if (attention > 0 || (normal > 0 && notTested > 0)) status = 'attention';
  else if (waiting > 0 && normal === 0) status = 'waiting';
  else if (waiting > 0) status = 'attention';
  else status = 'normal';

  return { status, total, normal, abnormal, notTested };
}

/** 合并控制端与节点端对同一检查项的展示状态，不让正常结果覆盖更保守的状态。 */
export function aggregateCheckDisplayStatuses(statuses: DiagnosisDisplayStatus[]): DiagnosisDisplayStatus {
  const tested = statuses.filter((status) => status !== 'not_tested');
  if (tested.length === 0) return 'not_tested';
  const abnormal = tested.filter((status) => status === 'abnormal').length;
  if (abnormal > 0) return abnormal === tested.length ? 'abnormal' : 'partial';
  if (tested.includes('unknown')) return 'unknown';
  if (tested.includes('waiting')) return 'waiting';
  if (tested.includes('partial')) return 'partial';
  if (tested.includes('attention')) return 'attention';
  return 'normal';
}

function targetCounts(results: DiagnoseTargetResult[]) {
  const reachable = results.filter((result) => result.outcome !== 'timeout' && 'reachable' in result.outcome).length;
  return { reachable, total: results.length };
}

function checkPriority(check: RealityCheck): number {
  if (check.state === 'fail') return 5;
  if (check.state === 'blocked') return 4;
  if (check.state === 'warning') return 3;
  if (!['pass', 'not_tested'].includes(check.state)) return 2;
  if (check.state === 'pass') return 1;
  return 0;
}

/** 合并单个节点同一层的检查。已完成的正常检查不会被未测试项削弱，
 * 明确问题和未来未知状态则必须继续保留。 */
export function combineDiagnosisChecks(checks: Array<RealityCheck | undefined | null>): RealityCheck {
  const present = checks.filter((check): check is RealityCheck => !!check);
  if (present.length === 0) return { state: 'not_tested' };
  return present.reduce((selected, check) => (
    checkPriority(check) > checkPriority(selected) ? check : selected
  ));
}

function backendCheck(results: DiagnoseTargetResult[]): RealityCheck {
  if (results.length === 0) return { state: 'not_tested' };
  const reachable = results.filter((result) => result.outcome !== 'timeout' && 'reachable' in result.outcome).length;
  if (reachable === results.length) return { state: 'pass' };
  if (reachable === 0) {
    const firstFailure = results.find((result) => result.outcome !== 'timeout' && 'failed' in result.outcome);
    return {
      state: 'fail',
      detail: firstFailure && firstFailure.outcome !== 'timeout' && 'failed' in firstFailure.outcome
        ? firstFailure.outcome.failed.error
        : undefined,
    };
  }
  return { state: 'warning' };
}

export function nodeListenerDisplayStatus(node: NodeDiagnoseStatus): DiagnosisDisplayStatus {
  if (node.status !== 'result') return 'not_tested';
  if (node.reality) return diagnosisDisplayStatus(node.reality.runtime.check);
  return node.listener_running ? 'normal' : 'abnormal';
}

export function aggregateNodeListeners(nodes: NodeDiagnoseStatus[]): DiagnosisAggregate {
  return aggregateDiagnosisStatuses(nodes.map(nodeListenerDisplayStatus));
}

export function nodeBackendDisplayStatus(node: NodeDiagnoseStatus): DiagnosisDisplayStatus {
  if (node.status !== 'result') return 'not_tested';
  if (!node.reality) return diagnosisDisplayStatus(backendCheck(node.results));
  const statuses = node.reality.backends.map((backend) => diagnosisDisplayStatus(backend.check));
  return aggregateDiagnosisStatuses(statuses).status;
}

export function aggregateNodeBackends(nodes: NodeDiagnoseStatus[]): DiagnosisAggregate {
  return aggregateDiagnosisStatuses(nodes.map(nodeBackendDisplayStatus));
}

export function aggregateNodeChecks(checks: RealityCheck[]): DiagnosisDisplayStatus {
  return aggregateDiagnosisStatuses(checks.map(diagnosisDisplayStatus)).status;
}

function realityBackendCheck(node: Extract<NodeDiagnoseStatus, { status: 'result' }>): RealityCheck {
  const backends = node.reality?.backends ?? [];
  if (backends.length === 0) return { state: 'not_tested' };
  const passed = backends.filter((backend) => backend.check.state === 'pass').length;
  if (passed === backends.length) return { state: 'pass' };
  if (passed === 0) return combineDiagnosisChecks(backends.map((backend) => backend.check));
  const detail = backends.find((backend) => backend.check.state !== 'pass')?.check.detail;
  return { state: 'warning', detail };
}

export function nodeDiagnosisChecks(node: NodeDiagnoseStatus): DiagnosisCheckSummary[] {
  if (node.status !== 'result') {
    return [{ key: 'node_response', check: { state: 'warning' } }];
  }
  if (!node.reality) {
    return [
      { key: 'listener', check: { state: node.listener_running ? 'pass' : 'fail' } },
      { key: 'backend', check: backendCheck(node.results) },
    ];
  }

  const reality = node.reality;
  return [
    { key: 'config', check: combineDiagnosisChecks([reality.config.check, reality.convergence.check]) },
    { key: 'nginx', check: reality.nginx.check },
    { key: 'route', check: combineDiagnosisChecks([reality.runtime.check, reality.convergence.check]) },
    {
      key: 'certificate',
      check: combineDiagnosisChecks([
        reality.certificate.check,
        reality.certificate.tls_handshake,
        reality.certificate.renewal,
      ]),
    },
    { key: 'camouflage', check: combineDiagnosisChecks([reality.camouflage.check, reality.fallback.check]) },
    { key: 'backend', check: realityBackendCheck(node) },
    { key: 'client_path', check: reality.vless_authentication },
  ];
}

function nodeRealityServiceSummary(
  node: Extract<NodeDiagnoseStatus, { status: 'result' }>,
): { check: RealityCheck; causeKey?: DiagnosisCheckKey } {
  const reality = node.reality;
  if (!reality) return { check: { state: 'not_tested' } };
  const checks: Array<{ key: DiagnosisCheckKey; check: RealityCheck }> = [
    { key: 'config', check: reality.config.check },
    { key: 'nginx', check: reality.nginx.check },
    { key: 'route', check: reality.runtime.check },
    { key: 'config', check: reality.convergence.check },
    { key: 'camouflage', check: reality.camouflage.check },
    { key: 'camouflage', check: reality.fallback.check },
  ];
  const check = combineDiagnosisChecks(checks.map((item) => item.check));
  const causeKey = checks.find((item) => diagnosisDisplayStatus(item.check) === diagnosisDisplayStatus(check))?.key;
  return { check, causeKey };
}

export function nodeDiagnosisIssues(node: NodeDiagnoseStatus): DiagnosisCheckSummary[] {
  if (node.status !== 'result') {
    return [{ key: 'node_response', check: { state: 'warning' } }];
  }

  const highlights: DiagnosisCheckSummary[] = [];
  if (!node.reality && !node.listener_running) {
    highlights.push({ key: 'listener', check: { state: 'fail' } });
  }
  if (node.reality) {
    const service = nodeRealityServiceSummary(node);
    if (service.check.state !== 'pass' && service.check.state !== 'not_tested') {
      highlights.push({ key: 'reality_service', check: service.check, causeKey: service.causeKey });
    }
    const backend = realityBackendCheck(node);
    if (backend.state !== 'pass') {
      highlights.push({ key: 'backend', check: backend });
    }
    const certificate = combineDiagnosisChecks([
      node.reality.certificate.check,
      node.reality.certificate.tls_handshake,
      node.reality.certificate.renewal,
    ]);
    if (certificate.state !== 'pass' && certificate.state !== 'not_tested') {
      highlights.push({ key: 'certificate', check: certificate });
    }
    if (isIssue(node.reality.vless_authentication)) {
      highlights.push({ key: 'client_path', check: node.reality.vless_authentication });
    }
  } else {
    const backend = backendCheck(node.results);
    if (backend.state !== 'pass') {
      highlights.push({ key: 'backend', check: backend });
    }
  }
  return highlights;
}

/** 紧凑区域最多展示两个面向运维人员的问题。 */
export function nodeDiagnosisHighlights(node: NodeDiagnoseStatus): DiagnosisCheckSummary[] {
  return nodeDiagnosisIssues(node).slice(0, 2);
}

/** 聚合同一层的多节点检查；正常与明确异常混合时保留为规则级警告。 */
export function aggregateDiagnosisChecks(checks: RealityCheck[]): RealityCheck {
  if (checks.length === 0) return { state: 'not_tested' };
  const completed = checks.filter((check) => check.state !== 'not_tested');
  if (completed.length === 0) return { state: 'not_tested' };
  const passes = completed.filter((check) => check.state === 'pass').length;
  const issues = completed.filter((check) => check.state !== 'pass');
  if (issues.length === 0) return { state: 'pass' };
  if (passes > 0) {
    const combined = combineDiagnosisChecks(issues);
    if (diagnosisDisplayStatus(combined) === 'unknown') return combined;
    return { state: 'warning', detail: combined.detail };
  }
  return combineDiagnosisChecks(issues);
}

export function diagnosisOverview(
  nodes: NodeDiagnoseStatus[],
  dependencies?: {
    dnsmgr: RealityCheck;
    dns_sync: RealityCheck;
    certificate: RealityCheck;
    route: RealityCheck;
  } | null,
): DiagnosisCheckSummary[] {
  const byKey = new Map<DiagnosisCheckKey, RealityCheck[]>();
  for (const node of nodes) {
    for (const item of nodeDiagnosisChecks(node)) {
      const checks = byKey.get(item.key) ?? [];
      checks.push(item.check);
      byKey.set(item.key, checks);
    }
  }

  const hasReality = nodes.some((node) => node.status === 'result' && !!node.reality);
  if (!hasReality) {
    const keys: DiagnosisCheckKey[] = byKey.has('listener')
      ? ['listener', 'backend']
      : ['node_response'];
    return keys.map((key) => ({ key, check: aggregateDiagnosisChecks(byKey.get(key) ?? []) }));
  }

  const nodeCheck = (key: DiagnosisCheckKey) => aggregateDiagnosisChecks(byKey.get(key) ?? []);
  const realityNodes = nodes.filter(
    (node): node is Extract<NodeDiagnoseStatus, { status: 'result' }> => node.status === 'result' && !!node.reality,
  );
  const listener = aggregateDiagnosisChecks(
    realityNodes.map((node) => node.reality?.runtime.check ?? { state: 'not_tested' }),
  );
  const realityService = aggregateDiagnosisChecks(
    realityNodes.map((node) => nodeRealityServiceSummary(node).check),
  );
  return [
    {
      key: 'dns',
      check: dependencies
        ? combineDiagnosisChecks([dependencies.dnsmgr, dependencies.dns_sync])
        : { state: 'not_tested' },
    },
    { key: 'listener', check: listener },
    {
      key: 'certificate',
      check: dependencies
        ? combineDiagnosisChecks([dependencies.certificate, nodeCheck('certificate')])
        : nodeCheck('certificate'),
    },
    {
      key: 'reality_service',
      check: dependencies
        ? combineDiagnosisChecks([dependencies.route, realityService])
        : realityService,
    },
    { key: 'backend', check: nodeCheck('backend') },
    { key: 'client_path', check: nodeCheck('client_path') },
  ];
}

export function controlChecks(
  dependencies: {
    dnsmgr: RealityCheck;
    dns_sync: RealityCheck;
    certificate: RealityCheck;
    route: RealityCheck;
  },
): ControlCheckSummary[] {
  return [
    { key: 'dnsmgr', check: dependencies.dnsmgr },
    { key: 'dns_sync', check: dependencies.dns_sync },
    { key: 'certificate', check: dependencies.certificate },
    { key: 'route', check: dependencies.route },
  ];
}

/** 选择已有的控制端问题，不把它与节点故障强行建立因果关系；
 * 明确失败优先于下游等待项。 */
export function primaryControlIssue(
  dependencies: Parameters<typeof controlChecks>[0],
): ControlCheckSummary | null {
  const checks = controlChecks(dependencies);
  return checks.find(({ check }) => check.state === 'fail')
    ?? checks.find(({ check }) => check.state === 'warning')
    ?? checks.find(({ check }) => check.state === 'blocked')
    ?? null;
}

export function deriveNodeDiagnosisSummary(node: NodeDiagnoseStatus): NodeDiagnosisSummary {
  if (node.status !== 'result') return { level: 'warning', incomplete: true };

  if (!node.reality) {
    const { reachable, total } = targetCounts(node.results);
    const critical = !node.listener_running || (total > 0 && reachable === 0);
    const warning = total === 0 || reachable < total;
    return { level: critical ? 'critical' : warning ? 'warning' : 'normal', incomplete: false };
  }

  const reality = node.reality;
  const allBackendsFailed = reality.backends.length > 0
    && reality.backends.every((backend) => isFail(backend.check));
  const critical = [reality.config.check, reality.convergence.check, reality.nginx.check, reality.runtime.check]
    .some(isFail) || allBackendsFailed;
  const partialBackends = reality.backends.length === 0
    || reality.backends.some((backend) => isIssue(backend.check));
  const nonCriticalIssue = partialBackends || [
    reality.certificate.check,
    reality.certificate.renewal,
    reality.certificate.tls_handshake,
    reality.camouflage.check,
    reality.fallback.check,
    reality.vless_authentication,
  ].some(isIssue);
  const criticalWarning = [
    reality.config.check,
    reality.convergence.check,
    reality.nginx.check,
    reality.runtime.check,
  ].some((check) => ['warning', 'blocked'].includes(check.state));

  return {
    level: critical ? 'critical' : nonCriticalIssue || criticalWarning ? 'warning' : 'normal',
    incomplete: false,
  };
}

export function deriveDiagnosisConclusion(
  nodes: NodeDiagnoseStatus[],
  dependencies?: {
    dnsmgr: RealityCheck;
    dns_sync: RealityCheck;
    certificate?: RealityCheck;
    route?: RealityCheck;
  } | null,
): DiagnosisConclusionLevel {
  const summaries = nodes.map(deriveNodeDiagnosisSummary);
  const allCompleteCritical = summaries.length > 0
    && summaries.every((summary) => !summary.incomplete && summary.level === 'critical');
  if (allCompleteCritical) return 'unavailable';

  const panelIssue = !!dependencies
    && [dependencies.dnsmgr, dependencies.dns_sync].some(isIssue);
  if (nodes.length === 0 || panelIssue || summaries.some((summary) => summary.level !== 'normal')) {
    return 'partial';
  }
  return 'healthy';
}

export function backendSummary(results: DiagnoseTargetResult[]) {
  const reachable = results.filter((result) => result.outcome !== 'timeout' && 'reachable' in result.outcome);
  const elapsed = reachable
    .map((result) => result.outcome !== 'timeout' && 'reachable' in result.outcome ? result.outcome.reachable.elapsed_ms : 0);
  return {
    reachable: reachable.length,
    total: results.length,
    slowestMs: elapsed.length > 0 ? Math.max(...elapsed) : null,
  };
}
