import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { message } from 'antd';

// Mock the api client + auth hook before importing the page under test.
const { mockGet, mockPost } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPost: vi.fn() }));
const { mockUseAuth } = vi.hoisted(() => ({ mockUseAuth: vi.fn() }));

vi.mock('../api/client', () => ({
  default: { get: mockGet, post: mockPost, delete: vi.fn() },
}));
vi.mock('../auth/useAuth', () => ({ useAuth: mockUseAuth }));

import NodeStatus from './NodeStatus';
import { stableGroupedRows, compareNodeRows } from '../components/nodes/sort';
import { operationStatusLabel } from '../components/nodes/lifecycleStatus';
import type { BatchUpgradeOperation, NodeDisplayRow, NodeOperation } from '../api/types';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

// Flush all pending microtasks/promises under fake timers. We deliberately
// avoid @testing-library's waitFor here: it polls on real timers and hangs when
// fake timers are installed. advanceTimersByTimeAsync(ms) drains the promise
// queue deterministically instead.
const flush = (ms = 0) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

const adminNode = {
  group_id: 1, group_name: 'admin-grp', node_id: 'n1', online: true,
  cpu: 5, mem: 5, connections: 0, uptime: 100, last_seen: new Date().toISOString(),
};
const sharedNode = {
  group_id: 2, group_name: 'shared-grp', node_id: 's1', online: true, connections: 0,
};
const artifactCatalog = ok({
  config_protocol_version: 2,
  artifacts: [
    { architecture: 'amd64', available: true, version: '1.2.3', sha256: '0'.repeat(64) },
    { architecture: 'arm64', available: false, error: 'missing' },
  ],
});

const renderPage = () => render(<MemoryRouter><NodeStatus /></MemoryRouter>);

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockUseAuth.mockReset();
  vi.useFakeTimers();
});
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe('NodeStatus page data source', () => {
  it('admin reads /nodes + Panel artifact catalog (catalog fetched once, not polled)', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([adminNode]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    expect(screen.getByText('admin-grp')).toBeInTheDocument();
    expect(mockGet).toHaveBeenCalledWith('/nodes');
    expect(mockGet).toHaveBeenCalledWith('/admin/node-artifacts');
    expect(mockGet).not.toHaveBeenCalledWith('/nodes/shared');

    // version must NOT be polled: advance several intervals, still exactly one
    await flush(15000);
    const artifactCalls = mockGet.mock.calls.filter((c) => c[0] === '/admin/node-artifacts').length;
    expect(artifactCalls).toBe(1);
  });

  it('regular user reads /nodes/shared, never admin nodes or artifacts', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: false });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes/shared') return Promise.resolve(ok([sharedNode]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    expect(screen.getByText('shared-grp')).toBeInTheDocument();
    expect(mockGet).toHaveBeenCalledWith('/nodes/shared');
    expect(mockGet).not.toHaveBeenCalledWith('/nodes');
    expect(mockGet).not.toHaveBeenCalledWith('/admin/node-artifacts');
    expect(screen.queryByRole('button', { name: 'batchUpgradeAll' })).toBeNull();
  });

  it('mounts Relay preference management only for admin inbound groups', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([
        adminNode,
        { ...adminNode, group_id: 2, group_name: 'out-group', node_id: 'out-node' },
      ]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([
        { id: 1, group_type: 'in' },
        { id: 2, group_type: 'out' },
      ]));
      if (url === '/groups/1/relay-preference') return Promise.resolve(ok({
        group_id: 1,
        preferred_node_id: 'n1',
        preferred_node_public_ipv4: '203.0.113.10',
        pending_node_id: null,
        state: 'idle',
        started_at: null,
        last_error: null,
        nodes: [{ node_id: 'n1', public_ipv4: '203.0.113.10', online: true, ready: true, ready_reasons: [], preferred: true }],
      }));
      if (url === '/groups/1/carrier-affinity') return Promise.resolve(ok({
        group_id: 1,
        default_node_id: 'n1',
        active_policy: { bindings: [] },
        pending_policy: null,
        transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
        bindings: [],
        catalog_stale: false,
      }));
      if (url === '/groups/1/carrier-lines') return Promise.resolve(ok({ lines: [], stale: false }));
      if (url === '/admin/relay-schedules') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    expect(screen.getByText('defaultLineTitle')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'carrierAffinityTitle' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'relayScheduleTitle' })).toBeInTheDocument();
    expect(mockGet).toHaveBeenCalledWith('/groups/1/relay-preference');
    expect(mockGet).not.toHaveBeenCalledWith('/admin/relay-schedules');
    expect(mockGet).not.toHaveBeenCalledWith('/groups/2/relay-preference');
    fireEvent.click(screen.getByRole('tab', { name: 'relayScheduleTitle' }));
    await flush();
    expect(mockGet).toHaveBeenCalledWith('/admin/relay-schedules');
  });
});

describe('NodeStatus load-failure behavior', () => {
  it('shows the error result when the first admin load fails', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.reject(new Error('boom'));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    expect(screen.getByText('loadFailed')).toBeInTheDocument();
  });

  it('keeps the last good rows through a transient poll failure and resumes updates', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    let nodeCall = 0;
    const recovered = { ...adminNode, group_name: 'admin-grp-recovered' };
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/nodes') {
        nodeCall += 1;
        if (nodeCall === 1) return Promise.resolve(ok([adminNode]));
        if (nodeCall === 2) return Promise.reject(new Error('transient'));
        return Promise.resolve(ok([recovered]));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();
    expect(screen.getByText('admin-grp')).toBeInTheDocument();

    // 后台轮询失败时保留最后一次成功数据，不用错误页打断操作。
    await flush(5000);
    expect(screen.queryByText('loadFailed')).not.toBeInTheDocument();
    expect(screen.getByText('admin-grp')).toBeInTheDocument();

    await flush(5000);
    expect(screen.getByText('admin-grp-recovered')).toBeInTheDocument();
    expect(screen.queryByText('admin-grp')).not.toBeInTheDocument();
  });

  it('keeps the five-second poll from overlapping a slow request', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    type NodesResponse = { code: number; message: string; data: typeof adminNode[] };
    let resolveNodes!: (value: NodesResponse) => void;
    const pendingNodes = new Promise<NodesResponse>((resolve) => {
      resolveNodes = resolve;
    });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return pendingNodes;
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();
    await flush(10000);
    expect(mockGet.mock.calls.filter((call) => call[0] === '/nodes')).toHaveLength(1);

    resolveNodes(ok([adminNode]));
    await flush();
    await flush(5000);
    expect(mockGet.mock.calls.filter((call) => call[0] === '/nodes')).toHaveLength(2);
  });
});

describe('NodeStatus targeted diagnosis entry point', () => {
  const preference = (nodes = [
    { node_id: 'n1', public_ipv4: '192.0.2.10', online: true, ready: true, ready_reasons: [], preferred: true },
    { node_id: 'n2', public_ipv4: '192.0.2.11', online: true, ready: false, ready_reasons: ['CONTROL_CHANNEL_OFFLINE'], preferred: false },
  ]) => ok({
    group_id: 1,
    preferred_node_id: 'n1',
    preferred_node_public_ipv4: '192.0.2.10',
    pending_node_id: null,
    state: 'idle',
    started_at: null,
    last_error: null,
    rollback_error: null,
    dns_records: [],
    nodes,
  });

  function setup() {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockPost.mockResolvedValue(ok({ group_id: 1, node_id: 'n1', healthy: true, checks: [] }));
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([adminNode]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([{ id: 1, name: 'group-a', group_type: 'in' }]));
      if (url === '/groups/1/relay-preference') return Promise.resolve(preference());
      if (url === '/groups/1/carrier-affinity') return Promise.resolve(ok({
        group_id: 1,
        default_node_id: 'n1',
        active_policy: { bindings: [] },
        pending_policy: null,
        transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
        bindings: [],
        catalog_stale: false,
      }));
      if (url === '/groups/1/carrier-lines') return Promise.resolve(ok({ lines: [], stale: false }));
      if (url === '/admin/relay-schedules') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
  }

  it('shows diagnosis for the preferred node and keeps it enabled for a not-ready node', async () => {
    setup();
    renderPage();
    await flush();

    const preferred = screen.getByTestId('default-line-candidate-n1');
    const notReady = screen.getByTestId('default-line-candidate-n2');
    expect(within(preferred).getByRole('button', { name: /diagnose/ })).toBeEnabled();
    expect(within(notReady).getByRole('button', { name: /diagnose/ })).toBeEnabled();
  });

  it('opens the node-only diagnosis without loading or selecting a Rule', async () => {
    setup();
    renderPage();
    await flush();
    const row = screen.getByTestId('default-line-candidate-n1');
    fireEvent.click(within(row).getByRole('button', { name: /diagnose/ }));
    await flush();

    expect(mockPost).toHaveBeenCalledWith('/admin/nodes/1/n1/diagnose', {});
    expect(mockGet).not.toHaveBeenCalledWith('/rules');
  });
});

describe('NodeStatus log drawer', () => {
  const logNode = {
    ...adminNode,
    install_method: 'systemd',
    lifecycle_online: true,
    architecture: 'x86_64',
    node_version: '1.1.0-rc.8',
    config_protocol_version: 2,
  };

  const operation = (logs: string, action = 'logs') => ok({
    id: 'operation-1',
    group_id: 1,
    node_id: 'n1',
    action,
    status: 'SUCCESS',
    message: 'done',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    architecture: 'x86_64',
    current_version: '1.1.0-rc.8',
    logs,
  });

  function mockLogPage(logs: string, action = 'logs') {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([logNode]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([]));
      if (url === '/admin/nodes/1/n1/logs?lines=200') return Promise.resolve(operation(logs, action));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
  }

  it('shows Node logs controls and copies only the complete log body', async () => {
    mockLogPage('line one\nline two');
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    const success = vi.spyOn(message, 'success');

    renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'nodeLogs' }));
    await flush();

    expect(screen.getByText('nodeOperation_logs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /nodeCopyLogs/ })).toBeEnabled();
    expect(screen.getByRole('button', { name: /refresh/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /nodeCopyLogs/ }));
    await flush();
    expect(writeText).toHaveBeenCalledWith('line one\nline two');
    expect(success).toHaveBeenCalledWith('copied');
    success.mockRestore();
  });

  it('keeps copy disabled for empty logs and hides it for non-log operations', async () => {
    mockLogPage('');
    const first = renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'nodeLogs' }));
    await flush();
    expect(screen.getByRole('button', { name: /nodeCopyLogs/ })).toBeDisabled();
    first.unmount();

    mockLogPage('restart output', 'restart');
    renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'nodeLogs' }));
    await flush();
    expect(screen.queryByRole('button', { name: /nodeCopyLogs/ })).toBeNull();
  });
});

describe('NodeStatus background lifecycle operations', () => {
  const runningOperation: NodeOperation = {
    id: 'operation-running', group_id: 1, node_id: 'n1', action: 'upgrade', status: 'SENT',
    message: 'sent', created_at: '2026-09-08T00:00:00Z', updated_at: '2026-09-08T00:00:01Z',
    current_version: '1.1.11', target_version: '1.1.12', architecture: 'amd64',
  };

  it('uses action-aware VERIFYING labels', () => {
    const t = (key: string) => key;
    expect(operationStatusLabel({ ...runningOperation, action: 'restart', status: 'VERIFYING' }, t)).toBe('nodeOperationVerifyingRestart');
    expect(operationStatusLabel({ ...runningOperation, action: 'upgrade', status: 'VERIFYING' }, t)).toBe('nodeOperationVerifyingUpgrade');
    expect(operationStatusLabel({ ...runningOperation, action: 'uninstall', status: 'VERIFYING' }, t)).toBe('nodeOperationVerifyingUninstall');
  });

  it('closes a running Drawer, cancels UI polling, and never reopens on a late response', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    let resolvePoll!: (value: ReturnType<typeof ok<NodeOperation>>) => void;
    const latePoll = new Promise<ReturnType<typeof ok<NodeOperation>>>((resolve) => { resolvePoll = resolve; });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([{ ...adminNode, ...runningOperation, lifecycle_online: true, install_method: 'systemd' }]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([]));
      if (url === '/admin/node-operations') return Promise.resolve(ok([runningOperation]));
      if (url === '/admin/nodes/1/n1/logs?lines=200') return Promise.resolve(ok(runningOperation));
      if (url === '/admin/nodes/1/n1/operations/operation-running') return latePoll;
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    const page = renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'nodeLogs' }));
    await flush();
    expect(screen.getByText('nodeOperation_upgrade')).toBeInTheDocument();
    await flush(1000);
    expect(mockGet).toHaveBeenCalledWith('/admin/nodes/1/n1/operations/operation-running');
    fireEvent.click(document.querySelector('.ant-drawer-close') as HTMLElement);
    await flush();
    resolvePoll(ok({ ...runningOperation, status: 'VERIFYING' }));
    await flush();
    expect(document.querySelector('.ant-drawer-open')).toBeNull();
    expect(mockPost).not.toHaveBeenCalled();
    const calls = mockGet.mock.calls.filter((call) => call[0] === '/admin/nodes/1/n1/operations/operation-running').length;
    await flush(5000);
    expect(mockGet.mock.calls.filter((call) => call[0] === '/admin/nodes/1/n1/operations/operation-running')).toHaveLength(calls);
    page.unmount();
  });

  it('rediscovers an active operation and opens its latest detail explicitly', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([adminNode]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([]));
      if (url === '/admin/node-operations') return Promise.resolve(ok([runningOperation]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: /backgroundTasks/ }));
    expect(screen.getByText(/n1 · nodeOperation_upgrade/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'details' }));
    expect(screen.getByText('nodeOperation_upgrade')).toBeInTheDocument();
  });
});

describe('NodeStatus batch rolling upgrade', () => {
  const preview = {
    target_version: '1.1.12', total: 5, pending: 2, already_current: 1, offline: 1, skipped: 3,
    items: [],
  };
  const runningBatch: BatchUpgradeOperation = {
    id: 'batch-running', status: 'RUNNING' as const, target_version: '1.1.12',
    created_at: '2026-09-08T00:00:00Z', updated_at: '2026-09-08T00:00:01Z', created_by: 1,
    total: 2, pending: 1, running: 1, success: 0, failed: 0, skipped: 0,
    current_item: 'node-a',
    items: [
      { group_id: 1, node_id: 'node-a', current_version: '1.1.11', target_version: '1.1.12', architecture: 'amd64', status: 'RUNNING' as const },
      { group_id: 1, node_id: 'node-b', current_version: '1.1.11', target_version: '1.1.12', architecture: 'amd64', status: 'PENDING' as const },
    ],
  };

  function mockBatchPage(batches: typeof runningBatch[] = []) {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([adminNode]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([]));
      if (url === '/admin/node-operations') return Promise.resolve(ok([]));
      if (url === '/admin/nodes/batch-upgrades') return Promise.resolve(ok(batches));
      if (url === '/admin/nodes/batch-upgrade/preview') return Promise.resolve(ok(preview));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
  }

  it('renders preview counts and starts one backend batch request', async () => {
    mockBatchPage();
    mockPost.mockResolvedValue(ok(runningBatch));
    renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: /batchUpgradeAll/ }));
    await flush();
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('v1.1.12')).toBeInTheDocument();
    expect(within(dialog).getByText('2')).toBeInTheDocument();
    expect(within(dialog).getAllByText('1')).toHaveLength(3);
    fireEvent.click(within(dialog).getByRole('button', { name: 'batchUpgradeStart' }));
    await flush();
    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(mockPost).toHaveBeenCalledWith('/admin/nodes/batch-upgrade', {});
    expect(screen.getByText('batchUpgradeProgressTitle')).toBeInTheDocument();
    expect(screen.getByText('node-a · v1.1.11 → v1.1.12')).toBeInTheDocument();
  });

  it('closing a running batch Drawer stops UI polling without cancelling or reopening', async () => {
    mockBatchPage([runningBatch]);
    let resolvePoll!: (value: ReturnType<typeof ok<typeof runningBatch>>) => void;
    const latePoll = new Promise<ReturnType<typeof ok<typeof runningBatch>>>((resolve) => { resolvePoll = resolve; });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes') return Promise.resolve(ok([adminNode]));
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/groups') return Promise.resolve(ok([]));
      if (url === '/admin/node-operations') return Promise.resolve(ok([]));
      if (url === '/admin/nodes/batch-upgrades') return Promise.resolve(ok([runningBatch]));
      if (url === '/admin/nodes/batch-upgrade/batch-running') return latePoll;
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: /batchUpgradeAll/ }));
    await flush(1000);
    expect(mockGet).toHaveBeenCalledWith('/admin/nodes/batch-upgrade/batch-running');
    fireEvent.click(document.querySelector('.ant-drawer-open .ant-drawer-close') as HTMLElement);
    await flush();
    resolvePoll(ok({ ...runningBatch, success: 1, running: 0, pending: 1 }));
    await flush();
    expect(document.querySelector('.ant-drawer-open')).toBeNull();
    expect(mockPost).not.toHaveBeenCalled();
    const calls = mockGet.mock.calls.filter((call) => call[0] === '/admin/nodes/batch-upgrade/batch-running').length;
    await flush(5000);
    expect(mockGet.mock.calls.filter((call) => call[0] === '/admin/nodes/batch-upgrade/batch-running')).toHaveLength(calls);
  });

  it.each([
    ['SUCCESS', 2, 0, 'batchUpgradeStatus_SUCCESS'],
    ['PARTIAL_SUCCESS', 1, 1, 'batchUpgradeStatus_PARTIAL_SUCCESS'],
  ] as const)('rediscovers and renders %s summary', async (status, success, failed, label) => {
    const terminal = { ...runningBatch, status, success, failed, running: 0, pending: 0, current_item: null };
    mockBatchPage([terminal]);
    renderPage();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: /backgroundTasks/ }));
    expect(screen.getByText(new RegExp(label))).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'details' }));
    expect(screen.getByText('batchUpgradeProgressTitle')).toBeInTheDocument();
    expect(screen.getByText(`batchUpgradeSuccess: ${success}`)).toBeInTheDocument();
    expect(screen.getByText(`batchUpgradeFailed: ${failed}`)).toBeInTheDocument();
  });
});

// v0.4.16 PR3: the node-status board must render groups in a STABLE order
// independent of the API/KVS return order, and keep multi-node groups sorted
// within themselves. These pin the pure sort + the rendered DOM order.

// Minimal row factory (only the fields the sort touches + a label to find in
// the DOM). public_ip is the legacy fallback for public_ipv4. Typed as
// NodeDisplayRow so the sort calls are type-checked; missing optional fields
// are fine (they're undefined in the type).
const mk = (
  group_id: number,
  group_name: string,
  opts: Partial<{
    node_id: string;
    public_ipv4: string;
    public_ip: string;
    public_ipv6: string;
    online: boolean;
  }> = {},
): NodeDisplayRow =>
  ({
    group_id,
    group_name,
    node_id: opts.node_id ?? `node-${group_id}`,
    public_ipv4: opts.public_ipv4,
    public_ip: opts.public_ip,
    public_ipv6: opts.public_ipv6,
    online: opts.online ?? true,
    cpu: 0,
    mem: 0,
    connections: 0,
    uptime: 0,
    last_seen: '',
  }) as NodeDisplayRow;

describe('stableGroupedRows — pure ordering', () => {
  it('sorts groups by group_id ascending regardless of input order', () => {
    const rows = [mk(2, 'b'), mk(1, 'a'), mk(4, 'd'), mk(3, 'c')];
    const groups = stableGroupedRows(rows);
    expect(groups.map(([gid]) => gid)).toEqual([1, 2, 3, 4]);
  });

  it('produces identical output for the same set in different orders', () => {
    const set = [mk(3, 'c'), mk(1, 'a'), mk(2, 'b')];
    // Two permutations of the same set must yield identical group sequences.
    const a = stableGroupedRows([set[0], set[1], set[2]]);
    const b = stableGroupedRows([set[2], set[0], set[1]]);
    expect(b).toEqual(a);
  });

  it('sorts nodes within a group by public_ipv4 (then legacy public_ip fallback)', () => {
    const rows = [
      mk(1, 'g', { node_id: 'n3', public_ipv4: '9.9.9.9' }),
      mk(1, 'g', { node_id: 'n1', public_ipv4: '1.1.1.1' }),
      mk(1, 'g', { node_id: 'n2', public_ip: '5.5.5.5' }), // legacy field only
    ];
    const [[, group]] = stableGroupedRows(rows);
    expect(group.map((r) => r.node_id)).toEqual(['n1', 'n2', 'n3']);
  });

  it('breaks ties on public_ipv6 then node_id', () => {
    // Same ipv4 -> ipv4 decides; same ipv4+ipv6 -> node_id decides.
    const rows = [
      mk(1, 'g', { node_id: 'zeta', public_ipv4: '1.1.1.1', public_ipv6: 'b::2' }),
      mk(1, 'g', { node_id: 'alpha', public_ipv4: '1.1.1.1', public_ipv6: 'a::1' }),
      mk(1, 'g', { node_id: 'mid', public_ipv4: '1.1.1.1', public_ipv6: 'a::1' }),
    ];
    const [[, group]] = stableGroupedRows(rows);
    // ipv6 a::1 before b::2; within a::1, node_id alpha before mid.
    expect(group.map((r) => r.node_id)).toEqual(['alpha', 'mid', 'zeta']);
  });

  it('sorts empty/missing IPs last within a group (stable, no flicker)', () => {
    const rows = [
      mk(1, 'g', { node_id: 'blank' }), // no IP yet
      mk(1, 'g', { node_id: 'hasip', public_ipv4: '1.1.1.1' }),
    ];
    const [[, group]] = stableGroupedRows(rows);
    expect(group.map((r) => r.node_id)).toEqual(['hasip', 'blank']);
  });
});

describe('compareNodeRows — direct comparator', () => {
  it('returns 0 for fully-equal sort keys', () => {
    expect(
      compareNodeRows(
        mk(1, 'g', { node_id: 'x', public_ipv4: '1.1.1.1', public_ipv6: '::1' }),
        mk(2, 'other', { node_id: 'x', public_ipv4: '1.1.1.1', public_ipv6: '::1' }),
      ),
    ).toBe(0);
  });
});

describe('NodeStatus rendered group order is stable across refreshes', () => {
  // Find the DEEPEST element whose textContent is exactly `text` (a group
  // header label), then return its document position. Header labels render as
  // leaf Text nodes inside the Collapse header, so the deepest exact match is
  // the header itself — not a wrapping ancestor. compareDocumentPosition tells
  // us relative order without relying on fragile array indices.
  const docOrderIdx = (text: string): Element => {
    const matches = Array.from(document.querySelectorAll('*')).filter(
      (el) => el.textContent === text && el.children.length === 0,
    );
    if (matches.length === 0) throw new Error(`no leaf element with text "${text}"`);
    return matches[0];
  };
  // Returns true if a comes before b in document order.
  const isBefore = (a: Element, b: Element) =>
    // Node.DOCUMENT_POSITION_FOLLOWING = 4: b follows a.
    (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;

  it('renders groups in ascending group_id order even when the API returns them shuffled', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes')
        return Promise.resolve(
          ok([
            mk(2, 'grp-two'),
            mk(4, 'grp-four'),
            mk(1, 'grp-one'),
            mk(3, 'grp-three'),
          ]),
        );
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    // The four group headers must appear in ascending group_id order in the DOM.
    const labels = ['grp-one', 'grp-two', 'grp-three', 'grp-four'];
    for (let i = 1; i < labels.length; i++) {
      expect(isBefore(docOrderIdx(labels[i - 1]), docOrderIdx(labels[i]))).toBe(true);
    }
  });

  it('keeps the same rendered order when a later poll returns the same set reshuffled', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    let call = 0;
    const set = [mk(3, 'grp-three'), mk(1, 'grp-one'), mk(2, 'grp-two')];
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      if (url === '/nodes') {
        call += 1;
        // Second call returns the SAME set in a different order.
        return Promise.resolve(ok(call === 1 ? set : [set[1], set[2], set[0]]));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();
    const order = ['grp-one', 'grp-two', 'grp-three'];
    const isAscending = () => {
      for (let i = 1; i < order.length; i++) {
        if (!isBefore(docOrderIdx(order[i - 1]), docOrderIdx(order[i]))) return false;
      }
      return true;
    };
    expect(isAscending()).toBe(true);

    // Trigger the 5s poll (reshuffled payload). Same set, different order →
    // the rendered order must be IDENTICAL (still ascending group_id).
    await flush(5000);
    expect(isAscending()).toBe(true);
  });

  it('renders a multi-node group with stable node order (admin /nodes)', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes')
        return Promise.resolve(
          ok([
            mk(1, 'g', { node_id: 'n3', public_ipv4: '9.9.9.9' }),
            mk(1, 'g', { node_id: 'n1', public_ipv4: '1.1.1.1' }),
            mk(1, 'g', { node_id: 'n2', public_ipv4: '5.5.5.5' }),
          ]),
        );
      if (url === '/admin/node-artifacts') return Promise.resolve(artifactCatalog);
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    // The three IPs render in distinct table cells; the lowest-numbered IP
    // must appear first in document order (ipv4-ascending within the group).
    expect(isBefore(docOrderIdx('1.1.1.1'), docOrderIdx('5.5.5.5'))).toBe(true);
    expect(isBefore(docOrderIdx('5.5.5.5'), docOrderIdx('9.9.9.9'))).toBe(true);
  });

  it('regular user /nodes/shared gets the same stable ordering', async () => {
    mockUseAuth.mockReturnValue({ isAdmin: false });
    mockGet.mockImplementation((url: string) => {
      if (url === '/nodes/shared')
        return Promise.resolve(
          ok([
            mk(2, 'shared-two'),
            mk(1, 'shared-one'),
          ]),
        );
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderPage();
    await flush();

    expect(isBefore(docOrderIdx('shared-one'), docOrderIdx('shared-two'))).toBe(true);
  });
});
