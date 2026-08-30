import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiEnvelope, DiagnoseResponse, ForwardRule } from '../../api/types';

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
      }],
    },
  };
}

function renderModal(open = true) {
  return render(<RuleDiagnosisModal rule={rule} open={open} onClose={vi.fn()} isAdmin t={t} />);
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
});
