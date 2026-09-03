import { describe, expect, it } from 'vitest';
import type { NodeDiagnoseStatus, RealityDiagnosis, RealityCheck } from '../../api/types';
import {
  aggregateCheckDisplayStatuses,
  aggregateDiagnosisChecks,
  aggregateDiagnosisStatuses,
  aggregateNodeBackends,
  aggregateNodeListeners,
  deriveDiagnosisConclusion,
  deriveNodeDiagnosisSummary,
  diagnosisDisplayStatus,
  combineDiagnosisChecks,
  diagnosisOverview,
  nodeDiagnosisHighlights,
  nodeDiagnosisChecks,
  nodeListenerDisplayStatus,
  primaryControlIssue,
} from './summary';

const check = (state: RealityCheck['state'] = 'pass'): RealityCheck => ({ state });

function reality(overrides: Partial<RealityDiagnosis> = {}): RealityDiagnosis {
  return {
    convergence: { check: check(), desired_sni: 'q1.example.com', active_sni: 'q1.example.com', desired_config_revision: 1, active_config_revision: 1, desired_fingerprint: 'a', active_fingerprint: 'a' },
    config: { check: check(), listen_port: 443, sni: 'q1.example.com', targets: ['192.0.2.1:443'], send_proxy_protocol: true },
    nginx: { check: check(), plan_contains_rule: true, mapping_matches: true, managed_file_matches: true, config_valid: true, service_healthy: true },
    runtime: { check: check(), listen_443: true, listen_8443: true },
    backends: [{ address: '192.0.2.1:443', check: check(), elapsed_ms: 10 }],
    certificate: { check: check(), renewal: check(), certificate_status: 'active', san_match: true, cert_key_match: true, tls_handshake: check(), remaining_days: 80 },
    camouflage: { check: check(), site_status: 'active', tls_listener_port: 8443, local_backend: '127.0.0.1:5244', http_status: 200 },
    fallback: { check: check(), authenticated_reality_path: false, http_status: 200 },
    vless_authentication: check('not_tested'),
    ...overrides,
  };
}

function node(overrides: Partial<Extract<NodeDiagnoseStatus, { status: 'result' }>> = {}): NodeDiagnoseStatus {
  return {
    status: 'result',
    node_id: 'node-a',
    group_name: 'group-a',
    public_ip: '192.0.2.10',
    listener_running: true,
    listen_port: 443,
    protocol: 'tcp',
    transport: 'tcp',
    results: [{ address: '192.0.2.1:443', outcome: { reachable: { elapsed_ms: 10 } } }],
    reality: reality(),
    request_id: 'request-1',
    rule_id: 1,
    type: 'reality',
    ...overrides,
  };
}

describe('diagnosis summary semantics', () => {
  it.each([
    ['pass', 'normal'],
    ['fail', 'abnormal'],
    ['blocked', 'waiting'],
    ['not_tested', 'not_tested'],
    ['warning', 'attention'],
    ['future_state', 'unknown'],
  ] as const)('maps raw state %s to %s', (raw, display) => {
    expect(diagnosisDisplayStatus(check(raw))).toBe(display);
  });

  it('never maps an unknown raw state to abnormal', () => {
    expect(diagnosisDisplayStatus(check('future_state'))).toBe('unknown');
    expect(diagnosisDisplayStatus(check('future_state'))).not.toBe('abnormal');
  });

  it('uses partial only for an aggregate with mixed failures', () => {
    expect(aggregateDiagnosisStatuses(['normal', 'abnormal']).status).toBe('partial');
    expect(aggregateDiagnosisStatuses(['attention']).status).toBe('attention');
  });

  it('is healthy when all checks pass and VLESS authentication is not tested', () => {
    expect(deriveDiagnosisConclusion([node()])).toBe('healthy');
  });

  it('does not treat not_tested alone as a partial result', () => {
    expect(deriveNodeDiagnosisSummary(node()).level).toBe('normal');
  });

  it('is partial when a Panel dependency fails but the node is healthy', () => {
    expect(deriveDiagnosisConclusion([node()], { dnsmgr: check('fail'), dns_sync: check() })).toBe('partial');
  });

  it('is partial when one node fails and another is healthy', () => {
    expect(deriveDiagnosisConclusion([
      node(),
      node({ node_id: 'node-b', reality: reality({ runtime: { check: check('fail'), listen_443: false, listen_8443: true } }) }),
    ])).toBe('partial');
  });

  it('is unavailable when every completed node has a critical failure', () => {
    const failed = { check: check('fail'), listen_443: false, listen_8443: false };
    expect(deriveDiagnosisConclusion([
      node({ reality: reality({ runtime: failed }) }),
      node({ node_id: 'node-b', reality: reality({ runtime: failed }) }),
    ])).toBe('unavailable');
  });

  it('keeps a runtime failure plus an incomplete timeout as partial', () => {
    expect(deriveDiagnosisConclusion([
      node({ reality: reality({ runtime: { check: check('fail'), listen_443: false, listen_8443: true } }) }),
      { status: 'timeout', node_id: 'node-b', group_name: 'group-a', public_ip: '192.0.2.11' },
    ])).toBe('partial');
  });

  it('keeps unsupported or offline nodes as partial rather than healthy', () => {
    expect(deriveDiagnosisConclusion([
      { status: 'unsupported', node_id: 'node-a', node_version: '0.4.8', group_name: 'group-a' },
      { status: 'control_channel_offline', node_id: 'node-b', group_name: 'group-a' },
    ])).toBe('partial');
  });

  it('reports certificate or camouflage issues as partial when runtime is healthy', () => {
    expect(deriveDiagnosisConclusion([node({
      reality: reality({
        certificate: { ...reality().certificate, check: check('warning') },
        camouflage: { ...reality().camouflage, check: check('fail') },
      }),
    })])).toBe('partial');
  });

  it('builds the Reality overview only from checks returned by the current API', () => {
    const overview = diagnosisOverview([node()], {
      dnsmgr: check(),
      dns_sync: check(),
      certificate: check(),
      route: check(),
    });
    expect(overview.map((item) => item.key)).toEqual([
      'dns', 'listener', 'certificate', 'reality_service', 'backend', 'client_path',
    ]);
    expect(overview.find((item) => item.key === 'client_path')?.check.state).toBe('not_tested');
  });

  it('keeps a mixed multi-node failure visible as a rule-level warning', () => {
    const overview = diagnosisOverview([
      node(),
      node({
        node_id: 'node-b',
        reality: reality({ nginx: { ...reality().nginx, check: check('fail'), mapping_matches: false } }),
      }),
    ]);
    expect(overview.find((item) => item.key === 'reality_service')?.check.state).toBe('warning');
    expect(nodeDiagnosisChecks(node({
      reality: reality({ nginx: { ...reality().nginx, check: check('fail'), mapping_matches: false } }),
    })).find((item) => item.key === 'nginx')?.check.state).toBe('fail');
  });

  it('uses the Reality Nginx runtime instead of the absent generic listener', () => {
    const failedListener = node({ listener_running: false });
    const overview = diagnosisOverview([failedListener], {
      dnsmgr: check('fail'),
      dns_sync: check('blocked'),
      certificate: check('blocked'),
      route: check('blocked'),
    });
    expect(overview.find((item) => item.key === 'dns')?.check.state).toBe('fail');
    expect(overview.find((item) => item.key === 'listener')?.check.state).toBe('pass');
    expect(nodeListenerDisplayStatus(failedListener)).toBe('normal');
    expect(nodeDiagnosisHighlights(failedListener)).toEqual([]);

    const failedRuntime = node({
      listener_running: false,
      reality: reality({
        runtime: { check: check('fail'), listen_443: false, listen_8443: true },
      }),
    });
    expect(nodeListenerDisplayStatus(failedRuntime)).toBe('abnormal');
    expect(diagnosisOverview([failedRuntime]).find((item) => item.key === 'listener')?.check.state)
      .toBe('fail');
  });

  it('chooses a concrete control failure before downstream blocked checks', () => {
    expect(primaryControlIssue({
      dnsmgr: check(),
      dns_sync: check('fail'),
      certificate: check('blocked'),
      route: check('blocked'),
    })?.key).toBe('dns_sync');
  });

  it('keeps the RC9 conclusion independent from certificate and route dependencies', () => {
    expect(deriveDiagnosisConclusion([node()], {
      dnsmgr: check(),
      dns_sync: check(),
      certificate: check('fail'),
      route: check('blocked'),
    })).toBe('healthy');
  });

  it('keeps the RC9 Reality conclusion independent from listener_running', () => {
    expect(deriveNodeDiagnosisSummary(node({ listener_running: false })).level).toBe('normal');
    expect(deriveDiagnosisConclusion([node({ listener_running: false })])).toBe('healthy');
  });

  it('preserves future states through combine and node aggregation', () => {
    expect(combineDiagnosisChecks([check('future_state')]).state).toBe('future_state');
    expect(combineDiagnosisChecks([check('future_state'), check()]).state).toBe('future_state');
    expect(combineDiagnosisChecks([check('future_state'), check('not_tested')]).state).toBe('future_state');
    expect(aggregateDiagnosisChecks([check('future_state'), check()]).state).toBe('future_state');
    expect(diagnosisDisplayStatus(aggregateDiagnosisChecks([check('future_state'), check()]))).toBe('unknown');
  });

  it('uses conservative display aggregation without changing the RC9 conclusion', () => {
    expect(aggregateCheckDisplayStatuses(['normal', 'abnormal'])).toBe('partial');
    expect(aggregateCheckDisplayStatuses(['normal', 'attention'])).toBe('attention');
    expect(aggregateCheckDisplayStatuses(['normal', 'waiting'])).toBe('waiting');
    expect(aggregateCheckDisplayStatuses(['normal', 'unknown'])).toBe('unknown');
    expect(aggregateCheckDisplayStatuses(['normal', 'not_tested'])).toBe('normal');
    expect(aggregateCheckDisplayStatuses(['normal', 'normal'])).toBe('normal');
  });

  it('treats an ordinary TCP listener failure as critical and partial target reachability as warning', () => {
    expect(deriveNodeDiagnosisSummary(node({ reality: undefined, listener_running: false })).level).toBe('critical');
    expect(deriveNodeDiagnosisSummary(node({
      reality: undefined,
      results: [
        { address: '192.0.2.1:443', outcome: { reachable: { elapsed_ms: 10 } } },
        { address: '192.0.2.2:443', outcome: { failed: { error: 'refused' } } },
      ],
    })).level).toBe('warning');
  });

  it('aggregates ordinary listener failures without treating missing results as failures', () => {
    expect(aggregateNodeListeners([
      node({ reality: undefined }),
      node({ node_id: 'node-b', reality: undefined, listener_running: false }),
      { status: 'timeout', node_id: 'node-c', group_name: 'group-a' },
    ])).toMatchObject({ status: 'partial', total: 3, abnormal: 1, notTested: 1 });
    expect(aggregateNodeListeners([
      node({ reality: undefined, listener_running: false }),
      node({ node_id: 'node-b', reality: undefined, listener_running: false }),
    ]).status).toBe('abnormal');
  });

  it('aggregates backend probes as mixed, failed or untested from real node evidence', () => {
    const failedReality = reality({
      backends: [{ address: '192.0.2.1:443', check: check('fail') }],
    });
    expect(aggregateNodeBackends([
      node(),
      node({ node_id: 'node-b', reality: failedReality }),
    ]).status).toBe('partial');
    expect(aggregateNodeBackends([
      { status: 'timeout', node_id: 'node-c', group_name: 'group-a' },
    ]).status).toBe('not_tested');
  });
});
