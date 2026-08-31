import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CarrierAffinityView,
  CarrierLineCatalog,
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

function arrange(view = affinity(), lineCatalog = catalog) {
  mockGet.mockImplementation((url: string) => {
    if (url.endsWith('/carrier-affinity')) return Promise.resolve(ok(view));
    if (url.endsWith('/carrier-lines')) return Promise.resolve(ok(lineCatalog));
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  mockPut.mockResolvedValue(ok(view));
  return render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} />);
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
    expect(zhCN.carrierFollowDefault).toBe('跟随默认');
    expect(zhCN.carrierExplicitRelay).toBe('指定 Relay');
    expect(zhCN.carrierStateEffective).toBe('已生效');
    expect(zhCN.carrierStateApplying).toBe('应用中');
    expect(zhCN.carrierStateRollingBack).toBe('回滚中');
    expect(zhCN.carrierStateFailed).toBe('失败');
    expect(zhCN.carrierStateSplit).toBe('DNS 分裂');
    expect(enUS.carrierNotConfigured).toBe('Not configured separately');
    expect(enUS.carrierFollowDefault).toBe('Follow default');
    expect(enUS.carrierExplicitRelay).toBe('Specific Relay');
    expect(Object.values(zhCN)).not.toContain('继承上级');
  });

  it('shows configured FollowDefault, Explicit, unknown line, and Relay health', async () => {
    arrange();
    expect(await screen.findByTestId('carrier-binding-Dianxin_Shandong')).toBeInTheDocument();
    expect(screen.getByTestId('carrier-binding-Liantong')).toBeInTheDocument();
    expect(screen.getByTestId('carrier-binding-Unknown_Line')).toHaveTextContent('carrierUnknownLine');
    expect(screen.getAllByText('carrierFollowDefault').length).toBeGreaterThan(0);
    expect(screen.getByText('carrierExplicitRelay')).toBeInTheDocument();
    expect(screen.getByText('carrierRelayOffline')).toBeInTheDocument();
    expect(screen.getAllByText('carrierRelayReady').length).toBeGreaterThan(0);
    fireEvent.mouseDown(screen.getByLabelText('Dianxin_Shandong carrierSelectMode'));
    expect(await screen.findByText('carrierNotConfigured')).toBeInTheDocument();
  });

  it('loads the catalog on add and adds a line without flattening it into the main view', async () => {
    arrange(affinity({ active_policy: { bindings: [] }, bindings: [] }));
    await screen.findByText('carrierEmpty');
    fireEvent.click(screen.getByRole('button', { name: /carrierAddLine/ }));
    const dialog = await screen.findByRole('dialog');
    expect(mockGet).toHaveBeenCalledWith('/groups/7/carrier-lines');
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: 'carrierSelectLine' }));
    fireEvent.click(await screen.findByText('联通'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'add' }));
    expect(await screen.findByTestId('carrier-binding-Liantong')).toBeInTheDocument();
  });

  it('allows an unknown stale binding to be removed and submits the complete policy', async () => {
    const staleView = affinity({ catalog_stale: true });
    mockGet.mockImplementation((url: string) => {
      if (url.endsWith('/carrier-affinity')) return Promise.resolve(ok(staleView));
      return Promise.reject(new Error('catalog unavailable'));
    });
    mockPut.mockResolvedValue(ok(staleView));
    render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} />);

    await screen.findByTestId('carrier-binding-Unknown_Line');
    fireEvent.click(screen.getByRole('button', { name: 'carrierNotConfigured: Unknown_Line' }));
    expect(await screen.findByText('carrierProviderDecides', { exact: false })).toBeInTheDocument();
    fireEvent.click(await screen.findByText('delete'));
    const save = screen.getByRole('button', { name: /carrierSave/ });
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
    expect(screen.getByRole('button', { name: /carrierSave/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /carrierAddLine/ })).toBeDisabled();
  });

  it('blocks changed UPSERTs when the catalog is stale', async () => {
    arrange(affinity({ catalog_stale: true }), { ...catalog, stale: true });
    await screen.findByTestId('carrier-binding-Dianxin_Shandong');
    expect(screen.getByLabelText('Dianxin_Shandong carrierSelectMode')).toBeDisabled();
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
    }));
    await screen.findByTestId('carrier-binding-Dianxin_Shandong');
    expect(screen.getByRole('button', { name: /carrierAddLine/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /carrierSave/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'carrierNotConfigured: Unknown_Line' })).toBeDisabled();
  });
});
