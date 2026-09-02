import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Modal } from 'antd';
import type { ApiEnvelope, CarrierAffinityView, RelayPreferenceView, RelayReadyNode } from '../../api/types';
import { zhCN } from '../../i18n/zh-CN';
import type { Tfn } from './types';

const { mockGet, mockPost, mockCarrierAvailability } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockCarrierAvailability: { value: 'ready' as 'loading' | 'ready' | 'error' },
}));

vi.mock('../../api/client', () => ({ default: { get: mockGet, post: mockPost } }));
vi.mock('./RelaySchedulePanel', () => ({ RelaySchedulePanel: () => null }));
vi.mock('./CarrierAffinityPanel', async () => {
  const React = await import('react');
  const carrier: CarrierAffinityView = {
    group_id: 10,
    default_node_id: 'node-a',
    active_policy: { bindings: [
      { line_id: 'Dianxin', mode: 'follow_default', node_id: null },
      { line_id: 'Liantong', mode: 'node', node_id: 'node-c' },
    ] },
    pending_policy: null,
    transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
    bindings: [],
    catalog_stale: false,
  };
  return {
    CarrierAffinityPanel: ({ onViewChange, onCatalogChange, onAvailabilityChange }: {
      onViewChange: (view: CarrierAffinityView) => void;
      onCatalogChange: (catalog: { stale: boolean; lines: { id: string; name: string; parent: null }[] }) => void;
      onAvailabilityChange: (state: 'loading' | 'ready' | 'error') => void;
    }) => {
      React.useEffect(() => {
        onViewChange(mockCarrierAvailability.value === 'ready' ? carrier : null as unknown as CarrierAffinityView);
        onCatalogChange(mockCarrierAvailability.value === 'ready' ? { stale: false, lines: [
          { id: 'Dianxin', name: '电信', parent: null },
          { id: 'Liantong', name: '联通', parent: null },
        ] } : null as unknown as { stale: boolean; lines: { id: string; name: string; parent: null }[] });
        onAvailabilityChange(mockCarrierAvailability.value);
      }, [onAvailabilityChange, onCatalogChange, onViewChange]);
      return (
        <div>
          carrierPanel
          <button type="button" onClick={() => onAvailabilityChange('error')}>carrierRefreshFailed</button>
        </div>
      );
    },
  };
});

import { RelayPreferencePanel } from './RelayPreferencePanel';

const t = ((key: string) => key) as unknown as Tfn;
const zhT = ((key: keyof typeof zhCN) => zhCN[key]) as Tfn;
const ok = <T,>(data: T): ApiEnvelope<T> => ({ code: 0, message: 'ok', data });

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
    preferred_node_public_ipv4: '203.0.113.97',
    pending_node_id: null,
    state: 'idle',
    started_at: null,
    last_error: null,
    rollback_error: null,
    dns_records: [],
    nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b'), relayNode('node-c')],
    ...over,
  };
}

async function openSwitchConfirmation(nodeId = 'node-b') {
  const row = await screen.findByTestId(`default-line-candidate-${nodeId}`);
  const button = within(row).getByRole('button', { name: /setAsDefaultLine/ });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  return screen.findByRole('dialog', { name: 'relaySwitchConfirmTitle' });
}

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockCarrierAvailability.value = 'ready';
});

afterEach(() => {
  Modal.destroyAll();
  vi.useRealTimers();
});

describe('RelayPreferencePanel', () => {
  it('shows every default-line candidate directly with Chinese status and no switch drawer', async () => {
    mockGet.mockResolvedValue(ok(preference({
      preferred_node_public_ipv4: '64.118.154.53',
      nodes: [
        relayNode('node-a', { public_ipv4: '64.118.154.53', preferred: true }),
        relayNode('node-b', { public_ipv4: '64.118.144.159', online: false, ready: false, ready_reasons: ['STALE_STATUS'] }),
      ],
    })));
    render(<RelayPreferencePanel groupId={10} t={zhT} />);

    expect(await screen.findByText('默认线路')).toBeInTheDocument();
    expect(screen.getByTestId('relay-preference-current')).toHaveTextContent('当前默认: 64.118.154.53');
    const current = screen.getByTestId('default-line-candidate-node-a');
    expect(current).toHaveTextContent('当前默认');
    const notReady = screen.getByTestId('default-line-candidate-node-b');
    expect(notReady).toHaveTextContent('离线');
    expect(notReady).toHaveTextContent('未就绪');
    expect(notReady).toHaveTextContent('节点状态已过期');
    expect(within(notReady).queryByRole('button', { name: /设为默认线路/ })).toBeNull();
    expect(screen.queryByText('Relay 调度')).toBeNull();
  });

  it('falls back to node_id when the preferred Relay has no IPv4', async () => {
    mockGet.mockResolvedValue(ok(preference({ preferred_node_public_ipv4: null, nodes: [relayNode('node-a', { public_ipv4: null, preferred: true })] })));
    render(<RelayPreferencePanel groupId={10} t={zhT} />);
    expect(await screen.findByTestId('relay-preference-current')).toHaveTextContent('当前默认: node-a');
    expect(screen.getByTestId('default-line-candidate-node-a')).toHaveTextContent('node-a');
  });

  it('translates known Ready reasons with details and preserves unknown reason codes', async () => {
    mockGet.mockResolvedValue(ok(preference({
      preferred_node_id: null,
      nodes: [relayNode('node-x', {
        online: false,
        ready: false,
        ready_reasons: ['ACTIVE_RULE_MISSING:42', 'PUBLIC_IPV4_INVALID', 'FUTURE_REASON'],
      })],
    })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    const row = await screen.findByTestId('default-line-candidate-node-x');
    expect(row).toHaveTextContent('relayReadyActiveRuleMissing (42)');
    expect(row).toHaveTextContent('relayReadyIpv4Invalid');
    expect(row).toHaveTextContent('FUTURE_REASON');
  });

  it('derives switch impact from FollowDefault only and keeps Explicit separate', async () => {
    mockGet.mockResolvedValue(ok(preference()));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    const dialog = await openSwitchConfirmation();
    const impact = within(dialog).getByTestId('default-line-switch-impact');
    expect(impact).toHaveTextContent('电信: 203.0.113.97 → 203.0.113.98');
    expect(impact).toHaveTextContent('联通: relaySwitchImpactKeeps 203.0.113.99');
    expect(impact).toHaveTextContent('relaySwitchImpactUnconfigured');
    expect(impact).not.toHaveTextContent('移动');
  });

  it('submits node_id once, re-fetches authoritative state, and never posts an IP', async () => {
    const post = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet.mockResolvedValueOnce(ok(preference())).mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    mockPost.mockReturnValue(post.promise);
    render(<RelayPreferencePanel groupId={10} t={t} />);
    const dialog = await openSwitchConfirmation();
    const confirm = within(dialog).getByRole('button', { name: /relaySwitchConfirm/ });
    fireEvent.click(confirm);
    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(mockPost).toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: 'node-b' });
    expect(mockPost).not.toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: '203.0.113.98' });
    post.resolve(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
  });

  it('continues polling when the authoritative post-switch GET returns switching', async () => {
    vi.useFakeTimers();
    mockGet
      .mockResolvedValueOnce(ok(preference()))
      .mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })))
      .mockResolvedValueOnce(ok(preference({ state: 'idle', pending_node_id: null })));
    mockPost.mockResolvedValue(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    const row = screen.getByTestId('default-line-candidate-node-b');
    fireEvent.click(within(row).getByRole('button', { name: /setAsDefaultLine/ }));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    const dialog = screen.getByRole('dialog', { name: 'relaySwitchConfirmTitle' });
    fireEvent.click(within(dialog).getByRole('button', { name: /relaySwitchConfirm/ }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.getByText('relayPreferenceSwitchingTo: node-b')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(mockGet).toHaveBeenCalledTimes(3);
  });

  it('keeps every switch action locked while one POST is pending and rejects a second POST', async () => {
    const post = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet.mockResolvedValueOnce(ok(preference())).mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    mockPost.mockReturnValue(post.promise);
    render(<RelayPreferencePanel groupId={10} t={t} />);
    const dialog = await openSwitchConfirmation('node-b');
    fireEvent.click(within(dialog).getByRole('button', { name: /relaySwitchConfirm/ }));
    await act(async () => { await Promise.resolve(); });
    await waitFor(() => {
      expect(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /setAsDefaultLine/ })).toBeDisabled();
      expect(within(screen.getByTestId('default-line-candidate-node-c')).getByRole('button', { name: /setAsDefaultLine/ })).toBeDisabled();
    });
    fireEvent.click(within(screen.getByTestId('default-line-candidate-node-c')).getByRole('button', { name: /setAsDefaultLine/ }));
    expect(mockPost).toHaveBeenCalledTimes(1);
    post.resolve(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
  });

  it('locks switch actions while a manual refresh GET is pending', async () => {
    const refresh = deferred<ApiEnvelope<RelayPreferenceView>>();
    mockGet.mockResolvedValueOnce(ok(preference())).mockReturnValueOnce(refresh.promise);
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByTestId('default-line-candidate-node-b');
    fireEvent.click(screen.getByRole('button', { name: 'refresh' }));
    await waitFor(() => expect(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /setAsDefaultLine/ })).toBeDisabled());
    fireEvent.click(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /setAsDefaultLine/ }));
    expect(mockPost).not.toHaveBeenCalled();
    refresh.resolve(ok(preference()));
    await waitFor(() => expect(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /setAsDefaultLine/ })).toBeEnabled());
  });

  it('restores failed-state retry, reconfirm, and choosing another Ready line', async () => {
    mockGet.mockResolvedValue(ok(preference({ state: 'failed', pending_node_id: 'node-b', last_error: 'DNS_RECORD_CONFLICT' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    const preferred = await screen.findByTestId('default-line-candidate-node-a');
    expect(within(preferred).getByRole('button', { name: /relayPreferenceReconfirm/ })).toBeEnabled();
    expect(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /relayPreferenceRetry/ })).toBeEnabled();
    expect(within(screen.getByTestId('default-line-candidate-node-c')).getByRole('button', { name: /setAsDefaultLine/ })).toBeEnabled();
  });

  it.each(['switching', 'rolling_back', 'failed_manual_intervention'] as const)('locks every switch action in %s', async (state) => {
    mockGet.mockResolvedValue(ok(preference({ state, pending_node_id: 'node-b' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByTestId('default-line-candidate-node-b');
    for (const nodeId of ['node-a', 'node-b', 'node-c']) {
      const buttons = within(screen.getByTestId(`default-line-candidate-${nodeId}`)).queryAllByRole('button');
      expect(buttons.some((button) => button.hasAttribute('disabled'))).toBe(true);
    }
  });

  it('allows a backend-guarded switch when Carrier policy loading failed', async () => {
    mockCarrierAvailability.value = 'error';
    mockGet.mockResolvedValueOnce(ok(preference())).mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    mockPost.mockResolvedValue(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    const dialog = await openSwitchConfirmation('node-b');
    expect(within(dialog).getByText('carrierPolicyUnavailable')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: /relaySwitchConfirm/ }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: 'node-b' }));
  });

  it('warns on stale Carrier impact after refresh failure while keeping switch available', async () => {
    mockGet.mockResolvedValueOnce(ok(preference())).mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    mockPost.mockResolvedValue(ok(preference({ state: 'switching', pending_node_id: 'node-b' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByTestId('default-line-candidate-node-b');
    fireEvent.click(screen.getByRole('button', { name: 'carrierRefreshFailed' }));
    const dialog = await openSwitchConfirmation('node-b');
    expect(within(dialog).getByText('carrierPolicyUnavailable')).toBeInTheDocument();
    expect(within(dialog).queryByText('电信')).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: /relaySwitchConfirm/ }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/groups/10/relay-preference', { node_id: 'node-b' }));
  });

  it('does not retry after the initial request succeeds', async () => {
    vi.useFakeTimers();
    mockGet.mockResolvedValue(ok(preference()));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(1);
  });

  it('recovers through the bounded initial retry and clears the warning', async () => {
    vi.useFakeTimers();
    mockGet.mockRejectedValueOnce(new Error('temporary')).mockResolvedValueOnce(ok(preference()));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('relayPreferenceLoadFailed')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('relayPreferenceLoadFailed')).toBeNull();
  });

  it('stops after both bounded automatic retries fail', async () => {
    vi.useFakeTimers();
    mockGet.mockRejectedValue(new Error('persistent'));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
    expect(mockGet).toHaveBeenCalledTimes(3);
  });

  it('manual refresh cancels an outstanding automatic retry', async () => {
    vi.useFakeTimers();
    mockGet.mockRejectedValueOnce(new Error('temporary')).mockResolvedValueOnce(ok(preference()));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: 'refresh' }));
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
  });

  it('cleans the automatic retry timer when unmounted', async () => {
    vi.useFakeTimers();
    mockGet.mockRejectedValue(new Error('temporary'));
    const { unmount } = render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(1);
  });

  it.each([1, 2, 4])('renders all %i default-line candidates on the page', async (count) => {
    const nodes = Array.from({ length: count }, (_, index) => relayNode(`node-${index + 1}`, { preferred: index === 0 }));
    mockGet.mockResolvedValue(ok(preference({ preferred_node_id: nodes[0].node_id, nodes })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    for (const node of nodes) expect(await screen.findByTestId(`default-line-candidate-${node.node_id}`)).toBeInTheDocument();
  });

  it('shows line-aware rollback journal and polls until rollback finishes', async () => {
    vi.useFakeTimers();
    mockGet.mockResolvedValueOnce(ok(preference({
      state: 'rolling_back', pending_node_id: 'node-b', last_error: 'DNS_RECORD_CONFLICT',
      dns_records: [
        { rule_id: 1, fqdn: 'q1.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.97', target_value: '203.0.113.98', expected_value: '203.0.113.97', sync_state: 'PENDING', position: 'target', last_error: null },
        { rule_id: 1, fqdn: 'q1.example.com', line_id: 'Dianxin', line_key: 'dnsmgr:Dianxin', rollback_value: '203.0.113.97', target_value: '203.0.113.98', expected_value: '203.0.113.97', sync_state: 'PROPAGATED', position: 'rollback', last_error: null },
      ],
    }))).mockResolvedValueOnce(ok(preference({ state: 'failed_rolled_back' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByTestId('relay-dns-record-1-default')).toHaveTextContent('relayPreferenceDnsAtTarget');
    expect(screen.getByTestId('relay-dns-record-1-dnsmgr-Dianxin')).toHaveTextContent('relayPreferenceDnsAtPrevious');
    expect(screen.getByTestId('relay-dns-record-1-default')).toHaveTextContent('rulesStatusWaiting');
    expect(screen.getByTestId('relay-dns-record-1-default').querySelector('[data-raw-state="PENDING"]')).toBeInTheDocument();
    expect(screen.getByTestId('relay-dns-record-1-dnsmgr-Dianxin')).toHaveTextContent('rulesStatusNormal');
    expect(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /relayPreferenceSwitching/ })).toBeDisabled();
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(screen.getByText('relayPreferenceRolledBack')).toBeInTheDocument();
  });

  it('keeps split state locked and exposes the rollback failure', async () => {
    mockGet.mockResolvedValue(ok(preference({
      state: 'failed_manual_intervention', pending_node_id: 'node-b', last_error: 'DNS_RECORD_CONFLICT', rollback_error: 'ROLLBACK_SCHEDULING_FAILED',
      dns_records: [{ rule_id: 2, fqdn: 'q2.example.com', line_id: 'default', line_key: 'default', rollback_value: '203.0.113.97', target_value: '203.0.113.98', expected_value: '203.0.113.98', sync_state: 'CONFLICT', position: 'target', last_error: 'ROLLBACK_PROVIDER_CONFLICT' }],
    })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    expect(await screen.findByText('relayPreferenceManualIntervention')).toBeInTheDocument();
    expect(screen.getByText(/relaySwitchErrorRollbackScheduling/)).toBeInTheDocument();
    expect(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: /relayPreferenceRetry/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'refresh' })).toBeEnabled();
  });

  it('polls switching every five seconds and stops after idle', async () => {
    vi.useFakeTimers();
    mockGet.mockResolvedValueOnce(ok(preference({ state: 'switching', pending_node_id: 'node-b' }))).mockResolvedValueOnce(ok(preference({ state: 'idle' })));
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(2);
  });
});
