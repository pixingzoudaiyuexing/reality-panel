import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiEnvelope, RelayPreferenceView, RelayReadyNode } from '../../api/types';
import { zhCN } from '../../i18n/zh-CN';
import type { Tfn } from './types';

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}));

vi.mock('../../api/client', () => ({
  default: { get: mockGet, post: mockPost },
}));

vi.mock('./RelaySchedulePanel', () => ({
  RelaySchedulePanel: () => null,
}));

vi.mock('./CarrierAffinityPanel', () => ({
  CarrierAffinityPanel: () => null,
}));

import { RelayPreferencePanel } from './RelayPreferencePanel';

const t = ((key: string) => key) as unknown as Tfn;
const zhT = ((key: keyof typeof zhCN) => zhCN[key]) as Tfn;
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function relayNode(nodeId: string, over: Partial<RelayReadyNode> = {}): RelayReadyNode {
  return {
    node_id: nodeId,
    public_ipv4: `203.0.113.${nodeId.charCodeAt(nodeId.length - 1)}`,
    online: true,
    ready: true,
    ready_reasons: [],
    preferred: false,
    ...over,
  };
}

function preference(over: Partial<RelayPreferenceView> = {}): RelayPreferenceView {
  return {
    group_id: 10,
    preferred_node_id: 'node-a',
    preferred_node_public_ipv4: '203.0.113.10',
    pending_node_id: null,
    state: 'idle',
    started_at: null,
    last_error: null,
    rollback_error: null,
    dns_records: [],
    nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b')],
    ...over,
  };
}

function rowFor(nodeId: string): HTMLElement {
  return screen.getByTestId(`relay-preference-node-${nodeId}`);
}

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('RelayPreferencePanel', () => {
  it('uses Chinese node wording, IP-first identity, and translated states', async () => {
    mockGet.mockResolvedValue(ok(preference({
      preferred_node_public_ipv4: '64.118.154.53',
      nodes: [
        relayNode('node-a', { public_ipv4: '64.118.154.53', preferred: true }),
        relayNode('node-b', {
          public_ipv4: '64.118.144.159',
          online: false,
          ready: false,
          ready_reasons: ['STALE_STATUS'],
        }),
      ],
    })));

    const { container } = render(<RelayPreferencePanel groupId={10} t={zhT} />);
    await screen.findByText('64.118.144.159');

    expect(screen.getByText('节点')).toBeInTheDocument();
    expect(screen.queryByText('Relay 节点')).toBeNull();
    expect(screen.getByTestId('relay-preference-current')).toHaveTextContent('当前优选: 64.118.154.53');

    const preferredRow = rowFor('node-a');
    expect(within(preferredRow).getByText('64.118.154.53')).toBeInTheDocument();
    expect(within(preferredRow).getByText('node-a').closest('code')).not.toBeNull();
    expect(within(preferredRow).getByText('在线')).toBeInTheDocument();
    expect(within(preferredRow).getByText('就绪')).toBeInTheDocument();
    expect(within(preferredRow).getByText('当前优选')).toBeInTheDocument();

    const offlineRow = rowFor('node-b');
    expect(within(offlineRow).getByText('离线')).toBeInTheDocument();
    expect(within(offlineRow).getByText('未就绪')).toBeInTheDocument();
    expect(within(offlineRow).getByText('节点状态已过期')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/\b(?:PASS|Running|Ready)\b/);
  });

  it('falls back to node_id when preferred or row IPv4 is missing', async () => {
    mockGet.mockResolvedValue(ok(preference({
      preferred_node_public_ipv4: null,
      nodes: [relayNode('node-a', { public_ipv4: null, preferred: true })],
    })));

    render(<RelayPreferencePanel groupId={10} t={zhT} />);
    await screen.findByTestId('relay-preference-node-node-a');

    expect(screen.getByTestId('relay-preference-current')).toHaveTextContent('当前优选: node-a');
    const row = rowFor('node-a');
    expect(within(row).getByText('node-a')).toBeInTheDocument();
    expect(within(row).queryByText('-')).toBeNull();
  });

  it('does not retry after the initial request succeeds', async () => {
    vi.useFakeTimers();
    mockGet.mockResolvedValue(ok(preference()));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });

    expect(mockGet).toHaveBeenCalledTimes(1);
  });

  it('recovers when the first bounded automatic retry succeeds', async () => {
    vi.useFakeTimers();
    mockGet
      .mockRejectedValueOnce(new Error('temporary network failure'))
      .mockResolvedValueOnce(ok(preference()));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('relayPreferenceLoadFailed')).toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(1999); });
    expect(mockGet).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    await act(async () => { await Promise.resolve(); });

    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('relayPreferenceLoadFailed')).toBeNull();
    expect(screen.getByText('relayPreferenceCurrent')).toBeInTheDocument();
  });

  it('stops automatic retries after the two retry attempts fail', async () => {
    vi.useFakeTimers();
    mockGet.mockRejectedValue(new Error('persistent network failure'));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(60000); });

    expect(mockGet).toHaveBeenCalledTimes(3);
    expect(screen.getByText('relayPreferenceLoadFailed')).toBeInTheDocument();
  });

  it('cancels a pending automatic retry after a successful manual refresh', async () => {
    vi.useFakeTimers();
    mockGet
      .mockRejectedValueOnce(new Error('temporary network failure'))
      .mockResolvedValueOnce(ok(preference()));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: 'refresh' }));
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });

    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('relayPreferenceLoadFailed')).toBeNull();
  });

  it('cleans the automatic retry timer when unmounted', async () => {
    vi.useFakeTimers();
    mockGet.mockRejectedValue(new Error('temporary network failure'));

    const { unmount } = render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });

    expect(mockGet).toHaveBeenCalledTimes(1);
  });

  it.each([1, 2, 4])('renders an arbitrary %i Relay list from the GET response', async (count) => {
    const nodes = Array.from({ length: count }, (_, index) => relayNode(`node-${index + 1}`));
    mockGet.mockResolvedValue(ok(preference({ preferred_node_id: nodes[0].node_id, nodes })));

    render(<RelayPreferencePanel groupId={10} t={t} />);

    for (const node of nodes) {
      expect(await screen.findByTestId(`relay-preference-node-${node.node_id}`)).toBeInTheDocument();
    }
    expect(mockGet).toHaveBeenCalledWith('/groups/10/relay-preference');
  });

  it('renders idle preferred, switchable, and Not Ready actions correctly', async () => {
    mockGet.mockResolvedValue(ok(preference({
      nodes: [
        relayNode('node-a', { preferred: true }),
        relayNode('node-b'),
        relayNode('node-c', { ready: false, ready_reasons: ['CONTROL_CHANNEL_OFFLINE'] }),
      ],
    })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('node-c');

    expect(within(rowFor('node-a')).getByText('relayPreferenceCurrent')).toBeInTheDocument();
    expect(within(rowFor('node-a')).queryByRole('button')).toBeNull();
    expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ })).toBeEnabled();
    expect(within(rowFor('node-c')).getByRole('button', { name: /relayPreferenceUnavailable/ })).toBeDisabled();
  });

  it('disables every Relay action while one switch POST is pending', async () => {
    const post = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet.mockResolvedValue(ok(preference({
      nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b'), relayNode('node-c')],
    })));
    mockPost.mockReturnValue(post.promise);

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('node-c');
    fireEvent.click(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ }));

    await waitFor(() => {
      expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ })).toBeDisabled();
      expect(within(rowFor('node-c')).getByRole('button', { name: /relayPreferenceSet/ })).toBeDisabled();
    });
    post.resolve(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
  });

  it('cannot issue a second switch POST while the first POST is pending', async () => {
    const post = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet.mockResolvedValue(ok(preference({
      nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b'), relayNode('node-c')],
    })));
    mockPost.mockReturnValue(post.promise);

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('node-c');
    fireEvent.click(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ }));
    fireEvent.click(within(rowFor('node-c')).getByRole('button', { name: /relayPreferenceSet/ }));

    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(mockPost).toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: 'node-b' });
    expect(mockPost).not.toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: '203.0.113.98' });
    post.resolve(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
  });

  it('blocks switch actions while a manual refresh GET is pending', async () => {
    const refresh = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet
      .mockResolvedValueOnce(ok(preference()))
      .mockReturnValueOnce(refresh.promise);

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('node-b');
    fireEvent.click(screen.getByRole('button', { name: 'refresh' }));

    await waitFor(() => {
      expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ })).toBeDisabled();
    });
    fireEvent.click(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ }));
    expect(mockPost).not.toHaveBeenCalled();

    refresh.resolve(ok(preference()));
    await waitFor(() => {
      expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ })).toBeEnabled();
    });
  });

  it('keeps the old preferred visible and locks every action while switching', async () => {
    mockGet.mockResolvedValue(ok(preference({
      state: 'switching',
      pending_node_id: 'node-b',
      nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b'), relayNode('node-c')],
    })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('relayPreferenceSwitchingTo: node-b');

    expect(within(rowFor('node-a')).getByText('relayPreferenceCurrent')).toBeInTheDocument();
    expect(within(rowFor('node-b')).queryByText('relayPreferenceCurrent')).toBeNull();
    expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSwitching/ })).toBeDisabled();
    expect(within(rowFor('node-a')).getByRole('button', { name: /relayPreferenceSwitchLocked/ })).toBeDisabled();
    expect(within(rowFor('node-c')).getByRole('button', { name: /relayPreferenceSwitchLocked/ })).toBeDisabled();
  });

  it('shows failed state and allows retry, another Relay, and explicit rollback', async () => {
    mockGet.mockResolvedValue(ok(preference({
      state: 'failed',
      pending_node_id: 'node-b',
      last_error: 'PUBLIC_DNS_MULTIPLE_ANSWERS',
      nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b'), relayNode('node-c')],
    })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('relayPreferenceSwitchFailed');

    expect(screen.getByText(/relaySwitchErrorMultipleAnswers/)).toBeInTheDocument();
    expect(within(rowFor('node-a')).getByText('relayPreferenceCurrent')).toBeInTheDocument();
    expect(within(rowFor('node-a')).getByRole('button', { name: /relayPreferenceReconfirm/ })).toBeEnabled();
    expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceRetry/ })).toBeEnabled();
    expect(within(rowFor('node-c')).getByRole('button', { name: /relayPreferenceSet/ })).toBeEnabled();
  });

  it('shows rollback progress per domain, locks actions, and keeps polling', async () => {
    vi.useFakeTimers();
    mockGet
      .mockResolvedValueOnce(ok(preference({
        state: 'rolling_back',
        pending_node_id: 'node-b',
        last_error: 'DNS_RECORD_CONFLICT',
        dns_records: [
          { rule_id: 1, fqdn: 'q1.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'PENDING', position: 'target', last_error: null },
          { rule_id: 2, fqdn: 'q2.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'PROPAGATED', position: 'rollback', last_error: null },
        ],
      })))
      .mockResolvedValueOnce(ok(preference({ state: 'failed_rolled_back' })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByText('relayPreferenceRollingBack')).toBeInTheDocument();
    expect(within(screen.getByTestId('relay-dns-record-1-default')).getByText('relayPreferenceDnsAtTarget')).toBeInTheDocument();
    expect(within(screen.getByTestId('relay-dns-record-2-default')).getByText('relayPreferenceDnsAtPrevious')).toBeInTheDocument();
    expect(within(rowFor('node-a')).getByRole('button')).toBeDisabled();
    expect(within(rowFor('node-b')).getByRole('button')).toBeDisabled();

    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.getByText('relayPreferenceRolledBack')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
  });

  it('shows split DNS and rollback error when manual intervention is required', async () => {
    const diagnose = vi.fn();
    mockGet.mockResolvedValue(ok(preference({
      state: 'failed_manual_intervention',
      pending_node_id: 'node-b',
      last_error: 'DNS_RECORD_CONFLICT',
      rollback_error: 'ROLLBACK_SCHEDULING_FAILED',
      dns_records: [
        { rule_id: 1, fqdn: 'q1.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'PROPAGATED', position: 'rollback', last_error: null },
        { rule_id: 2, fqdn: 'q2.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'CONFLICT', position: 'target', last_error: 'ROLLBACK_PROVIDER_CONFLICT' },
      ],
    })));

    render(<RelayPreferencePanel groupId={10} t={t} onDiagnoseNode={diagnose} />);
    await screen.findByText('relayPreferenceManualIntervention');

    expect(screen.getByText(/relaySwitchErrorRollbackScheduling/)).toBeInTheDocument();
    expect(within(screen.getByTestId('relay-dns-record-1-default')).getByText('relayPreferenceDnsAtPrevious')).toBeInTheDocument();
    expect(within(screen.getByTestId('relay-dns-record-2-default')).getByText('relayPreferenceDnsAtTarget')).toBeInTheDocument();
    expect(within(rowFor('node-a')).getByRole('button', { name: /relayPreferenceReconfirm/ })).toBeDisabled();
    expect(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceRetry/ })).toBeDisabled();
    fireEvent.click(within(rowFor('node-a')).getByRole('button', { name: /diagnose/ }));
    expect(diagnose).toHaveBeenCalledWith(expect.objectContaining({ node_id: 'node-a' }));
    expect(screen.getByRole('button', { name: 'refresh' })).toBeEnabled();
  });

  it('renders unique line-aware DNS rows for one rule across default and FollowDefault lines', async () => {
    mockGet.mockResolvedValue(ok(preference({
      state: 'rolling_back',
      pending_node_id: 'node-b',
      dns_records: [
        { rule_id: 1, fqdn: 'q1.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'PENDING', position: 'target', last_error: null },
        { rule_id: 1, fqdn: 'q1.example.com', line_id: 'Dianxin_Shandong', line_key: 'dnsmgr:Dianxin_Shandong', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'PENDING', position: 'target', last_error: null },
        { rule_id: 1, fqdn: 'q1.example.com', line_id: 'Liantong', line_key: 'dnsmgr:Liantong', rollback_value: '203.0.113.10', target_value: '203.0.113.11', expected_value: '203.0.113.10', sync_state: 'PENDING', position: 'target', last_error: null },
      ] as RelayPreferenceView['dns_records'],
    })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    expect(await screen.findByTestId('relay-dns-record-1-default')).toHaveTextContent('relayPreferenceDefaultLine');
    expect(screen.getByTestId('relay-dns-record-1-dnsmgr-Dianxin_Shandong')).toHaveTextContent('Dianxin_Shandong');
    expect(screen.getByTestId('relay-dns-record-1-dnsmgr-Liantong')).toHaveTextContent('Liantong');
    expect(screen.getByTestId('relay-preference-dns-records').children).toHaveLength(4);
  });

  it('maps known Ready reasons with details and preserves unknown codes', async () => {
    mockGet.mockResolvedValue(ok(preference({
      preferred_node_id: null,
      nodes: [relayNode('node-x', {
        online: false,
        ready: false,
        ready_reasons: ['ACTIVE_RULE_MISSING:42', 'PUBLIC_IPV4_INVALID', 'FUTURE_REASON'],
      })],
    })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('node-x');

    const row = rowFor('node-x');
    expect(within(row).getByText(/relayReadyActiveRuleMissing \(42\)/)).toBeInTheDocument();
    expect(within(row).getByText(/relayReadyIpv4Invalid/)).toBeInTheDocument();
    expect(within(row).getByText(/FUTURE_REASON/)).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: /relayPreferenceUnavailable/ })).toBeDisabled();
  });

  it('does not optimistically change preferred and re-GETs after POST success', async () => {
    const post = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet
      .mockResolvedValueOnce(ok(preference()))
      .mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    mockPost.mockReturnValue(post.promise);

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByText('node-b');
    fireEvent.click(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ }));

    expect(within(rowFor('node-a')).getByText('relayPreferenceCurrent')).toBeInTheDocument();
    expect(within(rowFor('node-b')).queryByText('relayPreferenceCurrent')).toBeNull();
    expect(mockPost).toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: 'node-b' });

    post.resolve(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('relayPreferenceSwitchingTo: node-b')).toBeInTheDocument();
    expect(within(rowFor('node-a')).getByText('relayPreferenceCurrent')).toBeInTheDocument();
  });

  it('starts polling when the authoritative post-switch GET returns switching', async () => {
    vi.useFakeTimers();
    mockGet
      .mockResolvedValueOnce(ok(preference()))
      .mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })))
      .mockResolvedValueOnce(ok(preference({ state: 'idle', pending_node_id: null })));
    mockPost.mockResolvedValue(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(within(rowFor('node-b')).getByRole('button', { name: /relayPreferenceSet/ }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.getByText('relayPreferenceSwitchingTo: node-b')).toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(mockGet).toHaveBeenCalledTimes(3);
  });

  it('polls switching every five seconds and stops after idle', async () => {
    vi.useFakeTimers();
    mockGet
      .mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })))
      .mockResolvedValueOnce(ok(preference({ state: 'idle', pending_node_id: null })));

    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    expect(mockGet).toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('relayPreferenceSwitchingTo: node-b')).toBeNull();

    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
  });
});
