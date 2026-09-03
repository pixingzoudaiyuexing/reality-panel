import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CarrierAffinityView,
  CarrierLineCatalog,
  RelayDnsRecordView,
  RelayReadyNode,
} from '../../api/types';
import type { Tfn } from './types';
import { zhCN } from '../../i18n/zh-CN';
import { enUS } from '../../i18n/en-US';

const { mockGet, mockPut } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
}));

vi.mock('../../api/client', () => ({
  default: { get: mockGet, put: mockPut },
}));

import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { buildCarrierCatalogTree } from './carrierCatalog';

const t = ((key: string) => key) as unknown as Tfn;
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

const nodes: RelayReadyNode[] = [
  {
    node_id: 'node-a',
    public_ipv4: '203.0.113.5',
    online: true,
    ready: true,
    ready_reasons: [],
    preferred: true,
  },
  {
    node_id: 'node-b',
    public_ipv4: '203.0.113.6',
    online: false,
    ready: false,
    ready_reasons: ['CONTROL_CHANNEL_OFFLINE'],
    preferred: false,
  },
];

const catalog: CarrierLineCatalog = {
  stale: false,
  lines: [
    { id: 'Dianxin', name: '电信', parent: null },
    { id: 'Dianxin_Shandong', name: '电信 / 山东', parent: 'Dianxin' },
    { id: 'Liantong', name: '联通', parent: null },
  ],
};

function affinity(over: Partial<CarrierAffinityView> = {}): CarrierAffinityView {
  return {
    group_id: 7,
    default_node_id: 'node-a',
    active_policy: {
      bindings: [
        { line_id: 'Dianxin_Shandong', mode: 'follow_default', node_id: null },
        { line_id: 'Liantong', mode: 'node', node_id: 'node-b' },
        { line_id: 'Unknown_Line', mode: 'follow_default', node_id: null },
      ],
    },
    pending_policy: null,
    transaction: {
      kind: null,
      state: 'idle',
      started_at: null,
      last_error: null,
      rollback_error: null,
    },
    bindings: [
      {
        line_id: 'Dianxin_Shandong',
        mode: 'follow_default',
        node_id: null,
        effective_node_id: 'node-a',
        relay_health: 'ready',
        catalog_available: true,
        dns_state: 'effective',
      },
      {
        line_id: 'Liantong',
        mode: 'node',
        node_id: 'node-b',
        effective_node_id: 'node-b',
        relay_health: 'offline',
        catalog_available: true,
        dns_state: 'failed',
      },
      {
        line_id: 'Unknown_Line',
        mode: 'follow_default',
        node_id: null,
        effective_node_id: 'node-a',
        relay_health: 'ready',
        catalog_available: false,
        dns_state: 'effective',
      },
    ],
    catalog_stale: false,
    ...over,
  };
}

function arrange(view = affinity(), lineCatalog = catalog, dnsRecords: RelayDnsRecordView[] = []) {
  mockGet.mockImplementation((url: string) => {
    if (url.endsWith('/carrier-affinity')) return Promise.resolve(ok(view));
    if (url.endsWith('/carrier-lines')) return Promise.resolve(ok(lineCatalog));
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  mockPut.mockResolvedValue(ok(view));
  return render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} dnsRecords={dnsRecords} />);
}

async function openEditor() {
  fireEvent.click(await screen.findByRole('button', { name: /carrierEditPolicy/ }));
  return screen.findByRole('dialog', { name: 'carrierEditPolicy' }, { timeout: 3000 });
}

describe('CarrierAffinityPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('builds the provider parent field into a catalog tree only', () => {
    expect(buildCarrierCatalogTree(catalog.lines)).toEqual([
      {
        value: 'Dianxin',
        title: '电信',
        children: [{ value: 'Dianxin_Shandong', title: '电信 / 山东' }],
      },
      { value: 'Liantong', title: '联通' },
    ]);
  });

  it('uses the approved carrier vocabulary in Chinese and English', () => {
    expect(zhCN.carrierNotConfigured).toBe('不单独配置');
    expect(zhCN.carrierFollowDefault).toBe('跟随默认线路');
    expect(zhCN.carrierExplicitRelay).toBe('指定线路');
    expect(zhCN.carrierStateEffective).toBe('已生效');
    expect(zhCN.carrierStateApplying).toBe('应用中');
    expect(zhCN.carrierStateRollingBack).toBe('回滚中');
    expect(zhCN.carrierStateFailed).toBe('失败');
    expect(zhCN.carrierStateSplit).toBe('DNS 状态不一致');
    expect(enUS.carrierNotConfigured).toBe('Not configured separately');
    expect(enUS.carrierFollowDefault).toBe('Follow default line');
    expect(enUS.carrierExplicitRelay).toBe('Specified line');
    expect(Object.values(zhCN)).not.toContain('继承上级');
  });

  it('shows a read-only policy, target Relay, and server DNS state without claiming actual Relay', async () => {
    arrange();
    const follow = await screen.findByTestId('carrier-route-Dianxin_Shandong');
    expect(follow).toHaveTextContent('carrierFollowDefault → 203.0.113.5');
    expect(follow).toHaveTextContent('carrierDnsEffective');
    const explicit = screen.getByTestId('carrier-route-Liantong');
    expect(explicit).toHaveTextContent('carrierExplicitRelay → 203.0.113.6');
    expect(explicit).toHaveTextContent('carrierDnsFailed');
    expect(screen.getByTestId('carrier-route-Unknown_Line')).toHaveTextContent('carrierUnknownLine');
    expect(screen.queryByText('carrierActualRelay')).toBeNull();
    expect(screen.queryByRole('combobox')).toBeNull();
  });

  it('loads the catalog and adds a line inside the editor drawer only', async () => {
    arrange(affinity({ active_policy: { bindings: [] }, bindings: [] }));
    await screen.findByText('carrierEmpty');
    const dialog = await openEditor();
    fireEvent.click(within(dialog).getByRole('button', { name: /carrierAddLine/ }));
    expect(mockGet).toHaveBeenCalledWith('/groups/7/carrier-lines');
    await userEvent.click(within(dialog).getByRole('combobox', { name: 'carrierSelectLine' }));
    fireEvent.click(await screen.findByText('联通'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'add' }));
    expect(within(dialog).getByTestId('carrier-binding-Liantong')).toBeInTheDocument();
    expect(screen.queryByTestId('carrier-route-Liantong')).toBeNull();
  });

  it('allows an unknown stale binding to be removed and submits the complete policy', async () => {
    const staleView = affinity({ catalog_stale: true });
    mockGet.mockImplementation((url: string) => {
      if (url.endsWith('/carrier-affinity')) return Promise.resolve(ok(staleView));
      return Promise.reject(new Error('catalog unavailable'));
    });
    mockPut.mockResolvedValue(ok(staleView));
    render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} />);

    const dialog = await openEditor();
    fireEvent.click(within(dialog).getByRole('button', { name: 'carrierNotConfigured: Unknown_Line' }));
    expect(await screen.findByText('carrierProviderDecides', { exact: false })).toBeInTheDocument();
    fireEvent.click(await screen.findByText('delete'));
    const save = within(dialog).getByRole('button', { name: /carrierSave/ });
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith(
      '/groups/7/carrier-affinity',
      {
        bindings: [
          { line_id: 'Dianxin_Shandong', mode: 'follow_default', node_id: null },
          { line_id: 'Liantong', mode: 'node', node_id: 'node-b' },
        ],
      },
    ));
  });

  it.each([
    ['switching', 'carrierStateApplying'],
    ['rolling_back', 'carrierStateRollingBack'],
    ['failed', 'carrierStateFailed'],
    ['failed_rolled_back', 'carrierStateFailed'],
    ['failed_manual_intervention', 'carrierStateSplit'],
  ] as const)('maps %s to the compact Chinese-facing state key', async (state, label) => {
    arrange(affinity({ transaction: { ...affinity().transaction, state, kind: 'carrier_policy_apply' } }));
    expect((await screen.findAllByText(label)).length).toBeGreaterThan(0);
  });

  it.each([
    ['effective', 'carrierDnsEffective'],
    ['applying', 'carrierDnsApplying'],
    ['pending', 'carrierDnsPending'],
    ['failed', 'carrierDnsFailed'],
  ] as const)('maps server DNS state %s without treating the target as an observed Relay', async (dnsState, label) => {
    const view = affinity({
      bindings: affinity().bindings.map((binding) => binding.line_id === 'Dianxin_Shandong'
        ? { ...binding, dns_state: dnsState }
        : binding),
    });
    arrange(view);
    const route = await screen.findByTestId('carrier-route-Dianxin_Shandong');
    expect(route).toHaveTextContent(label);
    expect(route).toHaveTextContent('203.0.113.5');
    expect(route).not.toHaveTextContent('carrierActualRelay');
  });

  it.each([
    ['future_state', 'carrierDnsUnknown'],
    ['failed', 'carrierDnsFailed'],
  ] as const)('distinguishes DNS state %s from an explicit failure', async (dnsState, label) => {
    arrange(affinity({
      bindings: affinity().bindings.map((binding) => binding.line_id === 'Dianxin_Shandong'
        ? { ...binding, dns_state: dnsState }
        : binding),
    }));
    const route = await screen.findByTestId('carrier-route-Dianxin_Shandong');
    expect(route).toHaveTextContent(label);
    if (dnsState !== 'failed') expect(route).not.toHaveTextContent('carrierDnsFailed');
  });

  it('locks duplicate saves while a topology transaction is active', async () => {
    arrange(affinity({
      pending_policy: { bindings: [{ line_id: 'Dianxin', mode: 'follow_default', node_id: null }] },
      transaction: {
        kind: 'carrier_policy_apply',
        state: 'switching',
        started_at: '2026-08-31T00:00:00Z',
        last_error: null,
        rollback_error: null,
      },
    }));
    expect(await screen.findByText('carrierBusy')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /carrierEditPolicy/ })).toBeDisabled();
  });

  it('retains cached policy but reports unavailable after the latest refresh fails', async () => {
    vi.useFakeTimers();
    const availability = vi.fn();
    let affinityCalls = 0;
    const switching = affinity({ transaction: { ...affinity().transaction, state: 'switching', kind: 'carrier_policy_apply' } });
    mockGet.mockImplementation((url: string) => {
      if (url.endsWith('/carrier-lines')) return Promise.resolve(ok(catalog));
      if (url.endsWith('/carrier-affinity')) {
        affinityCalls += 1;
        return affinityCalls === 1 ? Promise.resolve(ok(switching)) : Promise.reject(new Error('refresh failed'));
      }
      return Promise.reject(new Error(`unexpected URL ${url}`));
    });
    render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} onAvailabilityChange={availability} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByTestId('carrier-route-Dianxin_Shandong')).toBeInTheDocument();
    expect(availability).toHaveBeenLastCalledWith('ready');

    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(screen.getByTestId('carrier-route-Dianxin_Shandong')).toBeInTheDocument();
    expect(availability).toHaveBeenLastCalledWith('error');
    vi.useRealTimers();
  });

  it('blocks changed UPSERTs when the catalog is stale', async () => {
    arrange(affinity({ catalog_stale: true }), { ...catalog, stale: true });
    const dialog = await openEditor();
    expect(within(dialog).getByText('carrierCatalogStale')).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Dianxin_Shandong carrierSelectMode')).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: /carrierAddLine/ })).toBeEnabled();
    expect(mockPut).not.toHaveBeenCalled();
  });

  it('freezes all topology controls after DNS split', async () => {
    arrange(affinity({
      transaction: {
        kind: 'carrier_policy_apply',
        state: 'failed_manual_intervention',
        started_at: '2026-08-31T00:00:00Z',
        last_error: 'DNS_RECORD_CONFLICT',
        rollback_error: 'DNS_OWNERSHIP_UNVERIFIED',
      },
    }), catalog, [
      { rule_id: 3, fqdn: 'op1.example.com', line_id: 'Dianxin_Shandong', line_key: 'dnsmgr:Dianxin_Shandong', rollback_value: '203.0.113.5', target_value: '203.0.113.6', expected_value: '203.0.113.6', sync_state: 'PROPAGATED', position: 'target', last_error: null },
      { rule_id: 4, fqdn: 'op2.example.com', line_id: 'Dianxin_Shandong', line_key: 'dnsmgr:Dianxin_Shandong', rollback_value: '203.0.113.5', target_value: '203.0.113.6', expected_value: '203.0.113.5', sync_state: 'CONFLICT', position: 'rollback', last_error: 'DNS_RECORD_CONFLICT' },
      { rule_id: 5, fqdn: 'op3.example.com', line_id: 'Dianxin_Shandong', line_key: 'dnsmgr:Dianxin_Shandong', rollback_value: '203.0.113.5', target_value: '203.0.113.6', expected_value: null, sync_state: 'FAILED', position: 'unknown', last_error: 'READBACK_FAILED' },
    ]);
    expect(await screen.findByText('carrierSplitTitle')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /carrierEditPolicy/ })).toBeDisabled();
    const split = screen.getByTestId('carrier-split-details');
    expect(split).toHaveTextContent('op1.example.com');
    expect(split).toHaveTextContent('op2.example.com');
    expect(split).toHaveTextContent('op3.example.com');
    expect(split).toHaveTextContent('carrierAtTarget');
    expect(split).toHaveTextContent('carrierAtRollback');
    expect(split).toHaveTextContent('carrierAtUnknown');
    expect(split).toHaveTextContent('carrierRecordFailed');
  });

  it.each([
    [null, 'carrierRecordUnknown'],
    ['FUTURE_STATE', 'carrierRecordUnknown'],
    ['FAILED', 'carrierRecordFailed'],
  ] as const)('distinguishes record state %s from an explicit failure', async (syncState, label) => {
    arrange(affinity({
      transaction: {
        kind: 'carrier_policy_apply', state: 'failed_manual_intervention', started_at: null,
        last_error: 'DNS_RECORD_CONFLICT', rollback_error: 'READBACK_FAILED',
      },
    }), catalog, [{
      rule_id: 9, fqdn: 'op9.example.com', line_id: 'Dianxin_Shandong', line_key: 'dnsmgr:Dianxin_Shandong',
      rollback_value: '203.0.113.5', target_value: '203.0.113.6', expected_value: null,
      sync_state: syncState, position: 'unknown', last_error: null,
    }]);
    const split = await screen.findByTestId('carrier-split-details');
    expect(split).toHaveTextContent(label);
    if (syncState !== 'FAILED') expect(split).not.toHaveTextContent('carrierRecordFailed');
  });
});
