import type { DiagnoseTargetResult, NodeDiagnoseStatus, RealityCheck } from '../../api/types';

export type DiagnosisConclusionLevel = 'healthy' | 'partial' | 'unavailable';
export type NodeDiagnosisLevel = 'normal' | 'warning' | 'critical';

export interface NodeDiagnosisSummary {
  level: NodeDiagnosisLevel;
  incomplete: boolean;
}

const isIssue = (check?: RealityCheck | null) =>
  !!check && ['warning', 'fail', 'blocked'].includes(check.state);
const isFail = (check?: RealityCheck | null) => check?.state === 'fail';

function targetCounts(results: DiagnoseTargetResult[]) {
  const reachable = results.filter((result) => result.outcome !== 'timeout' && 'reachable' in result.outcome).length;
  return { reachable, total: results.length };
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
  dependencies?: { dnsmgr: RealityCheck; dns_sync: RealityCheck } | null,
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
