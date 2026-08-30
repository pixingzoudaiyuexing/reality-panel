import { describe, expect, it } from 'vitest';
import type { NodeDiagnoseStatus, RealityDiagnosis, RealityCheck } from '../../api/types';
import { deriveDiagnosisConclusion, deriveNodeDiagnosisSummary } from './summary';

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
});
