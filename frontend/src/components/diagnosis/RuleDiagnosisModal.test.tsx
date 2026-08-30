import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiEnvelope, DiagnoseResponse, ForwardRule } from '../../api/types';
import { zhCN } from '../../i18n/zh-CN';

const { mockPost } = vi.hoisted(() => ({ mockPost: vi.fn() }));

vi.mock('../../api/client', () => ({ default: { post: mockPost } }));

import { RuleDiagnosisModal } from './RuleDiagnosisModal';

const t = (key: string) => key;
const rule = { id: 7, name: 'q1', device_group_in: 1 } as ForwardRule;

function response(): ApiEnvelope<DiagnoseResponse> {
  return {
    code: 0,
    message: 'ok',
    data: {
      request_id: 'request-1',
      rule_id: 7,
      dependencies: {
        dnsmgr: { state: 'pass' },
        dns_sync: { state: 'pass' },
        certificate: { state: 'pass' },
        route: { state: 'pass' },
        blocking_chain: [],
      },
      nodes: [{
        status: 'result',
        node_id: 'node-a',
        group_name: 'group-a',
        public_ip: '192.0.2.10',
        listener_running: true,
        listen_port: 443,
        protocol: 'tcp',
        transport: 'tcp',
        results: [{ address: '192.0.2.1:443', outcome: { reachable: { elapsed_ms: 10 } } }],
        request_id: 'request-1',
        rule_id: 7,
        type: 'tcp',
        reality: {
          convergence: { check: { state: 'pass' }, desired_sni: 'q1.example.com', active_sni: 'q1.example.com', desired_config_revision: 1, active_config_revision: 1, desired_fingerprint: 'desired', active_fingerprint: 'active' },
          config: { check: { state: 'pass' }, listen_port: 443, sni: 'q1.example.com', targets: ['192.0.2.1:443'], send_proxy_protocol: true },
          nginx: { check: { state: 'pass' }, plan_contains_rule: true, mapping_matches: true, expected_fingerprint: 'expected-nginx', deployed_fingerprint: 'deployed-nginx', managed_file_matches: true, config_valid: true, service_healthy: true },
          runtime: { check: { state: 'pass' }, listen_443: true, listen_8443: true },
          backends: [{ address: '192.0.2.1:443', check: { state: 'pass' }, elapsed_ms: 10 }],
          certificate: { check: { state: 'pass' }, renewal: { state: 'pass' }, certificate_status: 'active', san_match: true, cert_key_match: true, tls_handshake: { state: 'pass' }, remaining_days: 80 },
          camouflage: { check: { state: 'pass' }, site_status: 'active', tls_listener_port: 8443, local_backend: '127.0.0.1:5244', http_status: 200 },
          fallback: { check: { state: 'pass' }, http_status: 200, authenticated_reality_path: false },
          vless_authentication: { state: 'not_tested' },
        },
      }],
    },
  };
}

function renderModal(open = true, translate: (key: string) => string = t) {
  return render(<RuleDiagnosisModal rule={rule} open={open} onClose={vi.fn()} isAdmin t={translate} />);
}

beforeEach(() => {
  mockPost.mockReset();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe('RuleDiagnosisModal request lifecycle', () => {
  it('automatically diagnoses when opened', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await act(async () => { await Promise.resolve(); });
    expect(mockPost).toHaveBeenCalledWith('/rules/7/diagnose');
    expect(screen.getByTestId('diagnosis-conclusion')).toBeInTheDocument();
    expect(screen.getByText('group-a · 192.0.2.10')).toBeInTheDocument();
  });

  it('does not issue a second request when the same rule is replaced by another object', async () => {
    mockPost.mockResolvedValue(response());
    const { rerender } = renderModal();
    await act(async () => { await Promise.resolve(); });
    rerender(<RuleDiagnosisModal rule={{ ...rule }} open onClose={vi.fn()} isAdmin t={t} />);
    await act(async () => { await Promise.resolve(); });
    expect(mockPost).toHaveBeenCalledTimes(1);
  });

  it('runs a second request only after an explicit manual refresh', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: /diagnosisRefresh/ }));
    await act(async () => { await Promise.resolve(); });
    expect(mockPost).toHaveBeenCalledTimes(2);
  });

  it('blocks concurrent manual refresh while the diagnosis request is pending', async () => {
    let resolve!: (value: ApiEnvelope<DiagnoseResponse>) => void;
    mockPost.mockReturnValue(new Promise<ApiEnvelope<DiagnoseResponse>>((done) => { resolve = done; }));
    renderModal();
    await act(async () => { await Promise.resolve(); });
    const refresh = screen.getByRole('button', { name: /diagnosisRefresh/ });
    expect(refresh).toBeDisabled();
    fireEvent.click(refresh);
    expect(mockPost).toHaveBeenCalledTimes(1);
    resolve(response());
    await act(async () => { await Promise.resolve(); });
  });

  it('does not poll diagnosis automatically after the initial request', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
    expect(mockPost).toHaveBeenCalledTimes(1);
  });

  it('shows the conclusion before node details and keeps technical details collapsed', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await act(async () => { await Promise.resolve(); });
    const conclusion = screen.getByTestId('diagnosis-conclusion');
    const nodes = screen.getByTestId('diagnosis-nodes');
    expect(conclusion.compareDocumentPosition(nodes) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('diagnosisExpandDetails')).toBeInTheDocument();
    expect(screen.queryByText('config_valid=true')).toBeNull();
  });

  it('uses the final Chinese conclusion labels and explains untested client authentication', async () => {
    mockPost.mockResolvedValue(response());
    renderModal(true, (key) => zhCN[key as keyof typeof zhCN]);
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByText(/诊断结论: 基本正常/)).toBeInTheDocument();
    expect(screen.getByText('完整客户端链路: 未测试')).toBeInTheDocument();
    expect(screen.getByText('当前节点不持有客户端认证凭据，因此无法执行完整客户端接入验证。该状态不代表故障。')).toBeInTheDocument();
    expect(screen.getByText('Panel 检查')).toBeInTheDocument();
    expect(screen.getByText('DNSMgr')).toBeInTheDocument();
    expect(screen.getByText('DNS 解析')).toBeInTheDocument();
  });

  it('keeps Nginx and Fallback evidence hidden until technical details expand', async () => {
    mockPost.mockResolvedValue(response());
    renderModal();
    await act(async () => { await Promise.resolve(); });

    expect(screen.queryByText(/plan_contains_rule=true/)).toBeNull();
    expect(screen.queryByText(/authenticated_reality_path=false/)).toBeNull();
    fireEvent.click(screen.getByText('diagnosisExpandDetails'));
    expect(screen.getByText(/plan_contains_rule=true/)).toBeInTheDocument();
    expect(screen.getByText(/expected_fingerprint=expected-nginx/)).toBeInTheDocument();
    expect(screen.getByText(/http_status=200 · authenticated_reality_path=false/)).toBeInTheDocument();
  });
});
