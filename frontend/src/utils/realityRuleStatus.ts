import type {
  CamouflageSiteStatus,
  ForwardRule,
  NodeStatus,
  RealityDiagnosis,
  RuleDnsStatus,
} from '../api/types';

export function normalizeSni(value?: string | null): string | undefined {
  const s = value?.trim().toLowerCase();
  return s || undefined;
}

export function isRealityRule(rule: Pick<ForwardRule, 'public_transport' | 'node_transport'>): boolean {
  return rule.public_transport === 'nginx_sni' || rule.node_transport === 'nginx_sni';
}

type RealityRuntimeChecks = {
  convergence: Pick<RealityDiagnosis['convergence'], 'check'>;
  config: Pick<RealityDiagnosis['config'], 'check'>;
  nginx: Pick<RealityDiagnosis['nginx'], 'check'>;
  runtime: Pick<RealityDiagnosis['runtime'], 'check'>;
};

export function diagnoseRuntimeStatus(listenerRunning: boolean, reality?: RealityRuntimeChecks) {
  if (!reality) {
    return {
      healthy: listenerRunning,
      labelKey: listenerRunning ? 'diagnoseListenerRunning' : 'diagnoseListenerStopped',
    };
  }
  const healthy = reality.config.check.state === 'pass'
    && reality.nginx.check.state === 'pass'
    && reality.runtime.check.state === 'pass'
    && reality.convergence.check.state === 'pass';
  return {
    healthy,
    labelKey: healthy ? 'diagnoseRealityRunning' : 'diagnoseRealityFailed',
  };
}

export function diagnosisStateDisplay(state: string, t: (key: string) => string) {
  if (state === 'pass') return { color: 'green', label: t('diagnosisPassed') };
  if (state === 'warning') return { color: 'gold', label: t('diagnosisWarning') };
  if (state === 'blocked') return { color: 'orange', label: t('diagnosisBlocked') };
  if (state === 'not_tested') return { color: 'default', label: t('diagnosisNotTested') };
  return { color: 'red', label: t('diagnosisFailedState') };
}

export function compactRealityStatus(
  rule: Pick<ForwardRule, 'camouflage_enabled'>,
  dns: RuleDnsStatus | undefined,
  camouflage: CamouflageAggregateStatus,
) {
  if (!rule.camouflage_enabled) return { dns: dns?.sync_state ?? '-', route: '-', certificate: '-' };
  const dnsValue = !dns || !dns.eligible ? '-' : dns.sync_state === 'PROPAGATED' ? 'OK' : dns.sync_state;
  const route = camouflage.state === 'active' ? 'OK' : camouflage.state === 'failed' ? 'FAIL' : camouflage.state.toUpperCase();
  const certificate = camouflage.certificate?.certificate_status === 'active'
    ? `OK${camouflage.certificate.valid_until ? ` ${Math.max(0, Math.floor((new Date(camouflage.certificate.valid_until).getTime() - Date.now()) / 86_400_000))}d` : ''}`
    : (camouflage.certificate?.certificate_status ?? 'PREPARING').toUpperCase();
  return { dns: dnsValue, route, certificate };
}

export type RuleHealthTone = 'normal' | 'waiting' | 'warning' | 'error' | 'unknown' | 'muted';

export interface RuleHealthDisplay {
  tone: RuleHealthTone;
  label: string;
  raw: string;
}

export function dnsSyncStateDisplay(state: string, t: (key: string) => string): RuleHealthDisplay {
  if (state === 'PROPAGATED') return { tone: 'normal', label: t('rulesStatusNormal'), raw: state };
  if (state === 'PENDING') return { tone: 'waiting', label: t('rulesStatusWaiting'), raw: state };
  if (['SYNCING', 'MUTATION_VERIFIED', 'PROPAGATING'].includes(state)) {
    return { tone: 'waiting', label: t('rulesStatusSyncing'), raw: state };
  }
  if (state === 'CONFLICT') return { tone: 'warning', label: t('rulesStatusConflict'), raw: state };
  if (state === 'DISABLED') return { tone: 'muted', label: t('rulesStatusDisabled'), raw: state };
  if (state === 'NOT_ELIGIBLE' || state === '-') {
    return { tone: 'muted', label: t('rulesStatusNotApplicable'), raw: state };
  }
  if (state === 'MUTATION_OUTCOME_UNKNOWN') {
    return { tone: 'error', label: t('rulesStatusUnknown'), raw: state };
  }
  if (['FAILED', 'INVALID_CONFIG'].includes(state)) {
    return { tone: 'error', label: t('rulesStatusAbnormal'), raw: state };
  }
  return { tone: 'unknown', label: t('rulesStatusUnknown'), raw: state };
}

export function runtimeStateDisplay(state: string, t: (key: string) => string): RuleHealthDisplay {
  const normalized = state.toLowerCase();
  if (['ok', 'active', 'propagated', 'converged'].includes(normalized)) {
    return { tone: 'normal', label: t('rulesStatusNormal'), raw: state };
  }
  if (['pending', 'preparing', 'syncing', 'propagating', 'withheld', 'reconciling', 'repairing'].includes(normalized)) {
    return { tone: 'waiting', label: t('rulesStatusWaiting'), raw: state };
  }
  if (['partial', 'renewal_warning', 'warning', 'dependency_withheld', 'degraded_local_recovery'].includes(normalized)) {
    return { tone: 'warning', label: t('rulesStatusWarning'), raw: state };
  }
  if (['fail', 'failed', 'failed_retrying', 'apply_failed', 'invalid_config'].includes(normalized)) {
    return { tone: 'error', label: t('rulesStatusAbnormal'), raw: state };
  }
  if (normalized === 'offline') return { tone: 'error', label: t('offline'), raw: state };
  if (normalized === 'disabled' || normalized === '-') {
    return { tone: 'muted', label: t('rulesStatusNotApplicable'), raw: state };
  }
  return { tone: 'unknown', label: t('rulesStatusUnknown'), raw: state };
}

export function compactRealityStatusDisplay(
  status: ReturnType<typeof compactRealityStatus>,
  t: (key: string) => string,
) {
  const dns = dnsSyncStateDisplay(status.dns === 'OK' ? 'PROPAGATED' : status.dns, t);
  const route = runtimeStateDisplay(status.route, t);
  const days = /^OK (\d+)d$/.exec(status.certificate);
  const certificate = days
    ? {
      tone: 'normal' as const,
      label: t('rulesStatusDaysRemaining').replace('{count}', days[1]),
      raw: status.certificate,
    }
    : runtimeStateDisplay(status.certificate, t);
  return { dns, route, certificate };
}

export function dnsOwnershipDisplay(ownership: RuleDnsStatus['ownership'], t: (key: string) => string) {
  if (ownership === 'PANEL_MANAGED') return t('dnsOwnershipPanelManaged');
  if (ownership === 'EXTERNAL') return t('dnsOwnershipExternal');
  return t('dnsOwnershipNone');
}

export function deriveCamouflageStatus(
  rule: Pick<ForwardRule, 'id' | 'camouflage_enabled' | 'sni' | 'device_group_in'>,
  nodes: NodeStatus[],
): CamouflageAggregateStatus {
  if (!rule.camouflage_enabled) {
    return { state: 'disabled', nodes: [], activeCount: 0, totalCount: 0 };
  }
  const sni = normalizeSni(rule.sni);
  const nodeViews: CamouflageNodeStatusView[] = nodes
    .filter(node => node.group_id === rule.device_group_in)
    .map(node => {
      const certificate = (node.camouflage_sites ?? []).find(site => site.sni === sni);
      const listenerState: CamouflageNodeStatusView['listenerState'] = node.active_listener_rule_ids == null
        ? 'unknown'
        : node.active_listener_rule_ids.includes(rule.id) ? 'active' : 'withheld';
      const fullyActive = node.online !== false
        && listenerState === 'active'
        && certificate?.site_status === 'active'
        && ['active', 'renewal_warning'].includes(certificate.certificate_status);
      let state: CamouflageNodeStatusView['state'];
      if (node.online === false) state = 'offline';
      else if (fullyActive) state = 'active';
      else if (
        ['failed', 'failed_retrying'].includes(certificate?.site_status ?? '')
        || ['failed', 'failed_retrying'].includes(certificate?.certificate_status ?? '')
      ) state = 'failed';
      else if (certificate || listenerState === 'withheld') state = 'preparing';
      else state = 'unknown';
      return {
        nodeId: node.node_id ?? undefined,
        relayIp: node.public_ipv4 ?? node.public_ip ?? node.public_ipv6 ?? undefined,
        listenerState,
        siteState: certificate?.site_status ?? 'unknown',
        certificateState: certificate?.certificate_status ?? 'unknown',
        lastError: certificate?.last_error ?? undefined,
        certificate,
        state,
      };
    })
    .sort((a, b) => {
      const aKey = `${a.relayIp ?? ''}\u0000${a.nodeId ?? ''}`;
      const bKey = `${b.relayIp ?? ''}\u0000${b.nodeId ?? ''}`;
      return aKey.localeCompare(bKey);
    });
  const activeNodes = nodeViews.filter(node => node.state === 'active');
  const preparingNodes = nodeViews.filter(node => node.state === 'preparing');
  const failedNodes = nodeViews.filter(node => node.state === 'failed');
  const totalCount = nodeViews.length;
  const activeCount = activeNodes.length;
  if (activeCount > 0) {
    return {
      state: activeCount === totalCount ? 'active' : 'partial',
      certificate: activeNodes[0].certificate,
      nodes: nodeViews,
      activeCount,
      totalCount,
    };
  }
  if (preparingNodes.length > 0) {
    return {
      state: 'preparing',
      certificate: preparingNodes[0].certificate,
      nodes: nodeViews,
      activeCount,
      totalCount,
    };
  }
  if (failedNodes.length > 0) {
    return {
      state: 'failed',
      certificate: failedNodes[0].certificate,
      nodes: nodeViews,
      activeCount,
      totalCount,
    };
  }
  return { state: 'unknown', nodes: nodeViews, activeCount, totalCount };
}

export function camouflageCertificateMessage(
  certificateState: string | undefined,
  error: string | undefined,
  translate: (key: string) => string,
): string | undefined {
  if (!error) return undefined;
  if (certificateState === 'active' || certificateState === 'renewal_warning') return translate('certificateRenewalWarning');
  if (error.toLowerCase().includes('dns')) return translate('camouflageDnsMismatch');
  return error;
}

export interface CamouflageNodeStatusView {
  nodeId?: string;
  relayIp?: string;
  listenerState: 'active' | 'withheld' | 'unknown';
  siteState: string;
  certificateState: string;
  lastError?: string;
  certificate?: CamouflageSiteStatus;
  state: 'active' | 'preparing' | 'failed' | 'unknown' | 'offline';
}

export interface CamouflageAggregateStatus {
  state: 'disabled' | 'unknown' | 'preparing' | 'active' | 'partial' | 'failed';
  certificate?: CamouflageSiteStatus;
  nodes: CamouflageNodeStatusView[];
  activeCount: number;
  totalCount: number;
}
