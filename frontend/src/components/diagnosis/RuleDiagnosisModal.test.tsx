import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiEnvelope, DiagnoseResponse, ForwardRule } from '../../api/types';
import { zhCN } from '../../i18n/zh-CN';

const { mockPost } = vi.hoisted(() => ({ mockPost: vi.fn() }));
vi.mock('../../api/client', () => ({ default: { post: mockPost } }));

import { RuleDiagnosisModal } from './RuleDiagnosisModal';

const t = (key: string) => key;
const zhT = (key: string) => zhCN[key as keyof typeof zhCN];
const realityRule = {
  id: 7, name: 'q1', device_group_in: 1, listen_port: 443, protocol: 'tcp',
  public_transport: 'nginx_sni', node_transport: 'nginx_sni',
} as ForwardRule;

function reality(overrides: Record<string, unknown> = {}) {
  return {
    convergence: { check: { state: 'pass' }, desired_sni: 'q1.example.com', active_sni: 'q1.example.com', desired_config_revision: 1, active_config_revision: 1, desired_fingerprint: 'desired', active_fingerprint: 'active' },
    config: { check: { state: 'pass' }, listen_port: 443, sni: 'q1.example.com', targets: ['192.0.2.1:443'], send_proxy_protocol: true },
    nginx: { check: { state: 'pass' }, plan_contains_rule: true, mapping_matches: true, expected_fingerprint: 'expected-nginx', deployed_fingerprint: 'deployed-nginx', managed_file_matches: true, config_valid: true, service_healthy: true },
    runtime: { check: { state: 'pass' }, listen_443: true, listen_8443: true },
    backends: [{ address: '192.0.2.1:443', check: { state: 'pass' }, elapsed_ms: 10 }],
    certificate: { check: { state: 'pass' }, renewal: { state: 'pass' }, certificate_status: 'active', san_match: true, cert_key_match: true, tls_handshake: { state: 'pass' }, remaining_days: 80, cert_path: '/cert/fullchain.pem', key_path: '/cert/privkey.pem' },
    camouflage: { check: { state: 'pass' }, site_status: 'active', tls_listener_port: 8443, local_backend: '127.0.0.1:5244', http_status: 200 },
    fallback: { check: { state: 'pass' }, http_status: 200, authenticated_reality_path: false },
    vless_authentication: { state: 'not_tested' },
    ...overrides,
  };
}

function diagnosedNode(id = 'node-a', ip = '192.0.2.10', overrides: Record<string, unknown> = {}) {
  return {
    status: 'result' as const, node_id: id, group_name: 'group-a', public_ip: ip,
    listener_running: true, listen_port: 443, protocol: 'tcp', transport: 'tcp',
    results: [{ address: '192.0.2.1:443', outcome: { reachable: { elapsed_ms: 10 } } }],
    request_id: 'request-1', rule_id: 7, type: 'tcp', reality: reality(),
    ...overrides,
  };
}

function response(
  nodes: DiagnoseResponse['nodes'] = [diagnosedNode()],
  dependencies: DiagnoseResponse['dependencies'] = {
    dnsmgr: { state: 'pass' }, dns_sync: { state: 'pass' },
    certificate: { state: 'pass' }, route: { state: 'pass' }, blocking_chain: [],
  },
): ApiEnvelope<DiagnoseResponse> {
  return { code: 0, message: 'ok', data: { request_id: 'request-1', rule_id: 7, dependencies, nodes } };
}

function renderModal(rule: ForwardRule = realityRule, translate: (key: string) => string = t) {
  return render(<RuleDiagnosisModal rule={rule} open onClose={vi.fn()} isAdmin t={translate} />);
}

async function settle() {
  await act(async () => { await Promise.resolve(); });
}

beforeEach(() => {
  mockPost.mockReset();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe('RuleDiagnosisModal table diagnosis', () => {
  it('automatically diagnoses once when opened and does not poll', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await settle();
    expect(mockPost).toHaveBeenCalledWith('/rules/7/diagnose');
    await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
    expect(mockPost).toHaveBeenCalledTimes(1);
  });

  it('refreshes only on explicit action and blocks concurrent refreshes', async () => {
    let resolve!: (value: ApiEnvelope<DiagnoseResponse>) => void;
    mockPost.mockReturnValue(new Promise((done) => { resolve = done; }));
    renderModal();
    await settle();
    const refresh = screen.getByRole('button', { name: /diagnosisRefresh/ });
    expect(refresh).toBeDisabled();
    fireEvent.click(refresh);
    expect(mockPost).toHaveBeenCalledTimes(1);
    resolve(response());
    await settle();
    fireEvent.click(screen.getByRole('button', { name: /diagnosisRefresh/ }));
    await settle();
    expect(mockPost).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['healthy', '正常'],
    ['partial', '部分异常'],
    ['unavailable', '不可用'],
  ] as const)('renders overall %s from the existing conclusion algorithm', async (level, label) => {
    const nodes = level === 'healthy'
      ? [diagnosedNode()]
      : level === 'partial'
        ? [diagnosedNode(), { status: 'timeout' as const, node_id: 'node-b', group_name: 'group-a' }]
        : [diagnosedNode('node-a', '192.0.2.10', { listener_running: false, reality: reality({ runtime: { check: { state: 'fail' }, listen_443: false, listen_8443: false } }) })];
    mockPost.mockResolvedValue(response(nodes));
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByTestId('diagnosis-conclusion')).toHaveTextContent('诊断结论: ' + label);
  });

  it('uses exactly six Reality check rows and two TCP check rows', async () => {
    mockPost.mockResolvedValue(response());
    const first = renderModal();
    await settle();
    expect(screen.getByTestId('diagnosis-check-table').querySelectorAll('tbody > tr:not(.ant-table-measure-row)')).toHaveLength(6);
    first.unmount();

    const tcpRule = { ...realityRule, public_transport: 'raw', node_transport: 'raw' } as ForwardRule;
    mockPost.mockResolvedValue(response([{ ...diagnosedNode(), reality: undefined }], undefined));
    renderModal(tcpRule);
    await settle();
    expect(screen.getByTestId('diagnosis-check-table').querySelectorAll('tbody > tr:not(.ant-table-measure-row)')).toHaveLength(2);
    expect(screen.queryByText('diagnosisDnsResolution')).toBeNull();
    expect(screen.queryByText('diagnosisCertificate')).toBeNull();
  });

  it('expresses DNSMgr failure and dns_sync failure without exposing DNSMgr in the main row', async () => {
    mockPost.mockResolvedValue(response(undefined, {
      dnsmgr: { state: 'fail', detail: 'provider unavailable' },
      dns_sync: { state: 'blocked', detail: 'DNSMgr is not ready' },
      certificate: { state: 'blocked' }, route: { state: 'blocked' }, blocking_chain: ['provider unavailable'],
    }));
    const first = renderModal(realityRule, zhT);
    await settle();
    const dnsRow = screen.getByText('DNS 解析').closest('tr') as HTMLElement;
    expect(dnsRow).toHaveTextContent('异常');
    expect(dnsRow).toHaveTextContent('DNS 管理服务异常，暂时无法确认解析状态');
    expect(dnsRow).not.toHaveTextContent('DNSMgr');
    first.unmount();

    mockPost.mockResolvedValue(response(undefined, {
      dnsmgr: { state: 'pass' }, dns_sync: { state: 'fail', detail: 'DNS_RECORD_CONFLICT' },
      certificate: { state: 'blocked' }, route: { state: 'blocked' }, blocking_chain: ['DNS_RECORD_CONFLICT'],
    }));
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByText('DNS 解析').closest('tr')).toHaveTextContent('域名尚未同步到目标线路');
  });

  it('renders blocked certificate and route as waiting, not abnormal', async () => {
    mockPost.mockResolvedValue(response(undefined, {
      dnsmgr: { state: 'pass' }, dns_sync: { state: 'fail' },
      certificate: { state: 'blocked', detail: 'Public DNS is not ready' },
      route: { state: 'blocked', detail: 'Public DNS is not ready' },
      blocking_chain: ['Public DNS is not ready'],
    }));
    renderModal(realityRule, zhT);
    await settle();
    const certificate = screen.getByText('证书').closest('tr') as HTMLElement;
    const route = screen.getByText('Reality 路由').closest('tr') as HTMLElement;
    expect(certificate).toHaveTextContent('等待');
    expect(certificate).not.toHaveTextContent('异常');
    expect(route).toHaveTextContent('等待');
  });

  it('shows mixed listeners as partial and all failed listeners as abnormal', async () => {
    mockPost.mockResolvedValue(response([
      diagnosedNode(),
      diagnosedNode('node-b', '192.0.2.11', { listener_running: false }),
    ]));
    const first = renderModal(realityRule, zhT);
    await settle();
    const checkTable = screen.getByTestId('diagnosis-check-table');
    expect(within(checkTable).getByText('监听服务').closest('tr')).toHaveTextContent('部分异常');
    expect(within(checkTable).getByText('监听服务').closest('tr')).toHaveTextContent('2 个节点中 1 个监听服务异常');
    first.unmount();

    mockPost.mockResolvedValue(response([
      diagnosedNode('node-a', '192.0.2.10', { listener_running: false }),
      diagnosedNode('node-b', '192.0.2.11', { listener_running: false }),
    ]));
    renderModal(realityRule, zhT);
    await settle();
    expect(within(screen.getByTestId('diagnosis-check-table')).getByText('监听服务').closest('tr')).toHaveTextContent('2 个节点监听服务均异常');
  });

  it('describes incomplete listener coverage without calling it an unknown state', async () => {
    mockPost.mockResolvedValue(response([
      diagnosedNode(),
      { status: 'timeout', node_id: 'node-b', group_name: 'group-a' },
    ]));
    renderModal(realityRule, zhT);
    await settle();
    const listener = within(screen.getByTestId('diagnosis-check-table')).getByText('监听服务').closest('tr');
    expect(listener).toHaveTextContent('需注意');
    expect(listener).toHaveTextContent('部分节点尚未完成监听检查');
    expect(listener).not.toHaveTextContent('状态未知');
  });

  it.each([
    ['certificate', 'fail', '部分异常'],
    ['certificate', 'warning', '需注意'],
    ['route', 'warning', '需注意'],
    ['route', 'blocked', '等待'],
    ['route', 'future_state', '状态未知'],
  ] as const)('keeps node-side %s %s visible when the control check passes', async (layer, state, expected) => {
    const nodeReality = layer === 'certificate'
      ? reality({ certificate: { ...reality().certificate, check: { state } } })
      : reality({ nginx: { ...reality().nginx, check: { state } } });
    mockPost.mockResolvedValue(response(
      [diagnosedNode('node-a', '192.0.2.10', { reality: nodeReality })],
      { dnsmgr: { state: 'pass' }, dns_sync: { state: 'pass' }, certificate: { state: 'pass' }, route: { state: 'pass' }, blocking_chain: [] },
    ));
    renderModal(realityRule, zhT);
    await settle();
    const label = layer === 'certificate' ? '证书' : 'Reality 路由';
    expect(screen.getByText(label).closest('tr')).toHaveTextContent(expected);
  });

  it('shows all-pass control and node checks as normal', async () => {
    mockPost.mockResolvedValue(response());
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByText('证书').closest('tr')).toHaveTextContent('正常');
    expect(screen.getByText('Reality 路由').closest('tr')).toHaveTextContent('正常');
  });

  it('surfaces a failed TLS handshake in the Certificate row without changing RC9 overall logic', async () => {
    const nodeReality = reality({
      certificate: { ...reality().certificate, check: { state: 'pass' }, tls_handshake: { state: 'fail' } },
    });
    mockPost.mockResolvedValue(response([diagnosedNode('node-a', '192.0.2.10', { reality: nodeReality })]));
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByTestId('diagnosis-conclusion')).toHaveTextContent('诊断结论: 部分异常');
    expect(screen.getByText('证书').closest('tr')).not.toHaveTextContent('正常');
    expect(screen.getByTestId('diagnosis-conclusion')).not.toHaveTextContent('0 项');
  });

  it('surfaces a renewal warning in the Certificate row', async () => {
    const nodeReality = reality({
      certificate: { ...reality().certificate, check: { state: 'pass' }, renewal: { state: 'warning' } },
    });
    mockPost.mockResolvedValue(response([diagnosedNode('node-a', '192.0.2.10', { reality: nodeReality })]));
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByText('证书').closest('tr')).toHaveTextContent('需注意');
  });

  it('maps a camouflage failure to the Reality route row with the real cause', async () => {
    const nodeReality = reality({ camouflage: { ...reality().camouflage, check: { state: 'fail' } } });
    mockPost.mockResolvedValue(response([diagnosedNode('node-a', '192.0.2.10', { reality: nodeReality })]));
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByTestId('diagnosis-conclusion')).toHaveTextContent('诊断结论: 部分异常');
    const route = screen.getByText('Reality 路由').closest('tr');
    expect(route).not.toHaveTextContent('正常');
    expect(route).toHaveTextContent('伪装站检查异常');
  });

  it('maps a fallback warning to the Reality route row with the real cause', async () => {
    const nodeReality = reality({ fallback: { ...reality().fallback, check: { state: 'warning' } } });
    mockPost.mockResolvedValue(response([diagnosedNode('node-a', '192.0.2.10', { reality: nodeReality })]));
    renderModal(realityRule, zhT);
    await settle();
    const route = screen.getByText('Reality 路由').closest('tr');
    expect(route).toHaveTextContent('需注意');
    expect(route).toHaveTextContent('回退链路存在警告');
  });

  it('never reports zero issues when every node response is incomplete', async () => {
    mockPost.mockResolvedValue(response([
      { status: 'timeout', node_id: 'node-a', group_name: 'group-a' },
      { status: 'unsupported', node_id: 'node-b', node_version: '0.4.8', group_name: 'group-a' },
      { status: 'control_channel_offline', node_id: 'node-c', group_name: 'group-a' },
    ]));
    renderModal(realityRule, zhT);
    await settle();
    const conclusion = screen.getByTestId('diagnosis-conclusion');
    expect(conclusion).toHaveTextContent('诊断结论: 部分异常');
    expect(conclusion).not.toHaveTextContent('0 项');
    expect(conclusion).toHaveTextContent('存在未完成或需关注的诊断结果');
  });

  it('never reports zero issues for waiting-only incomplete control checks', async () => {
    mockPost.mockResolvedValue(response([], {
      dnsmgr: { state: 'pass' }, dns_sync: { state: 'pass' },
      certificate: { state: 'blocked' }, route: { state: 'blocked' }, blocking_chain: [],
    }));
    renderModal(realityRule, zhT);
    await settle();
    const conclusion = screen.getByTestId('diagnosis-conclusion');
    expect(conclusion).toHaveTextContent('诊断结论: 部分异常');
    expect(conclusion).not.toHaveTextContent('0 项');
  });

  it('renders multiple nodes in one compact table and reports the primary issue plus more count', async () => {
    const failedReality = reality({
      nginx: { ...reality().nginx, check: { state: 'fail', detail: 'mapping mismatch' }, mapping_matches: false },
      certificate: { ...reality().certificate, check: { state: 'fail' } },
    });
    mockPost.mockResolvedValue(response([
      diagnosedNode(),
      diagnosedNode('node-b', '192.0.2.11', { listener_running: false, reality: failedReality }),
    ]));
    renderModal(realityRule, zhT);
    await settle();
    const table = screen.getByTestId('diagnosis-node-table');
    expect(within(table).getByText('192.0.2.10')).toBeInTheDocument();
    const failedRow = within(table).getByText('192.0.2.11').closest('tr') as HTMLElement;
    expect(failedRow).toHaveTextContent('规则监听器未正常运行');
    expect(failedRow).toHaveTextContent('另有');
  });

  it('keeps technical evidence hidden, expands one row at a time, and preserves raw values', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await settle();
    expect(screen.queryByText(/plan_contains_rule=true/)).toBeNull();

    const nodeTable = screen.getByTestId('diagnosis-node-table');
    fireEvent.click(within(nodeTable).getByRole('button', { name: 'diagnosisViewDetails' }));
    expect(screen.getByText(/plan_contains_rule=true/)).toBeInTheDocument();
    expect(screen.getByText(/desired=1 · active=1/)).toBeInTheDocument();
    expect(screen.getByText(/desired=desired · active=active/)).toBeInTheDocument();

    const dnsRow = screen.getByText('diagnosisDnsResolution').closest('tr') as HTMLElement;
    fireEvent.click(within(dnsRow).getByRole('button', { name: 'diagnosisViewDetails' }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.queryByText(/plan_contains_rule=true/)).toBeNull();
    expect(screen.getByText('DNSMgr')).toBeInTheDocument();
    expect(screen.getByText('dns_sync')).toBeInTheDocument();
  });

  it('does not render the removed section architecture or nested collapse', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await settle();
    expect(screen.queryByText('diagnosisOverview')).toBeNull();
    expect(screen.queryByText('diagnosisControlChecks')).toBeNull();
    expect(screen.queryByText('diagnosisNodeSummary')).toBeNull();
    expect(document.querySelector('.rp-diagnosis-modal .ant-collapse')).toBeNull();
    expect(screen.getByTestId('diagnosis-check-table')).toBeInTheDocument();
    expect(screen.getByTestId('diagnosis-node-table')).toBeInTheDocument();
  });

  it('shows an inline retry instead of a blank modal after request failure', async () => {
    mockPost.mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce(response());
    renderModal(realityRule, zhT);
    await settle();
    expect(screen.getByText('诊断结果加载失败')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }));
    await settle();
    expect(screen.getByTestId('diagnosis-check-table')).toBeInTheDocument();
  });
});
