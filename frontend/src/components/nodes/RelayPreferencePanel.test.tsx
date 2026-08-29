import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiEnvelope, RelayPreferenceView, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}));

vi.mock('../../api/client', () => ({
  default: { get: mockGet, post: mockPost },
}));

import { RelayPreferencePanel } from './RelayPreferencePanel';

const t = ((key: string) => key) as unknown as Tfn;
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
