import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { message } from 'antd';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CarrierAffinityView, CarrierLineCatalog, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';

const { mockGet, mockPut } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPut: vi.fn() }));
vi.mock('../../api/client', () => ({ default: { get: mockGet, put: mockPut } }));

import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { carrierApplyErrorMessage } from './carrierErrors';
import { assignCarrierLines, buildCarrierLineOptions, carrierLineMatchesSearch } from './carrierCatalog';

const translations: Record<string, string> = {
  carrierAllNetworkDefault: '全网默认',
  carrierErrorDefaultAuthority: '全网默认线路请使用“设为默认线路”功能管理',
  carrierErrorFailoverEnabled: '已启用故障切换，无法应用运营商线路策略',
  carrierErrorCatalogStale: '运营商线路目录已过期，请稍后重试',
  carrierErrorDnsMgrUnavailable: 'DNS 服务暂不可用',
  carrierErrorTransactionInProgress: '当前有线路事务正在执行',
  carrierErrorOwnershipUnverified: 'DNS 记录所有权无法确认',
  carrierErrorProviderPreflight: 'DNS 服务预检查失败',
  carrierSaveFailed: '运营商线路策略应用失败',
};
const t = ((key: string) => translations[key] ?? key) as Tfn;
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const nodes: RelayReadyNode[] = [
  { node_id: 'node-a', public_ipv4: '203.0.113.5', online: true, ready: true, ready_reasons: [], preferred: true },
  { node_id: 'node-b', public_ipv4: '203.0.113.6', online: false, ready: false, ready_reasons: ['CONTROL_CHANNEL_OFFLINE'], preferred: false },
];
const catalog: CarrierLineCatalog = {
  stale: false,
  lines: [
    { id: 'default', name: '全网默认', parent: null },
    { id: 'Dianxin', name: '电信', parent: null },
    { id: 'Liantong', name: '联通', parent: null },
    { id: 'Dianxin_Shanghai', name: '电信_上海', parent: 'Dianxin' },
    { id: 'Liantong_Shanghai', name: '联通_上海', parent: 'Liantong' },
    { id: 'Yidong_Shanghai', name: '移动_上海', parent: null },
    { id: 'Yidong_Sichuan', name: '移动_四川', parent: null },
  ],
};
const view: CarrierAffinityView = {
  group_id: 7,
  default_node_id: 'node-a',
  active_policy: { bindings: [
    { line_id: 'default', mode: 'node', node_id: 'node-a' },
    { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
  ] },
  pending_policy: null,
  transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
  bindings: [],
  catalog_stale: false,
};

function arrange(over: Partial<CarrierAffinityView> = {}, displayedNodes = nodes) {
  const response = { ...view, ...over };
  mockGet.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/carrier-lines') ? catalog : response)));
  mockPut.mockResolvedValue(ok(response));
  render(<CarrierAffinityPanel groupId={7} nodes={displayedNodes} t={t} />);
}

describe('CarrierAffinityPanel node-oriented editor', () => {
  beforeEach(() => vi.clearAllMocks());

  it('shows every Relay and keeps an offline Relay editable', async () => {
    arrange();
    expect(await screen.findByTestId('carrier-node-node-a')).toHaveTextContent('203.0.113.5');
    expect(screen.getByTestId('carrier-node-node-b')).toHaveTextContent('offline');
    expect(screen.getByLabelText('node-b carrierLine')).toBeEnabled();
  });

  it('moves one unique line between Relays', () => {
    expect(assignCarrierLines(view.active_policy.bindings, 'node-a', ['default', 'Dianxin'], view.default_node_id)).toEqual([
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-a' },
    ]);
  });

  it('removes a deselected legacy FollowDefault line from the default Relay', () => {
    expect(assignCarrierLines([
      { line_id: 'default', mode: 'follow_default', node_id: null },
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
    ], 'node-a', [], 'node-a')).toEqual([
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
    ]);
  });

  it('shows default only as a derived fixed indicator on the preferred Relay', async () => {
    arrange();
    const preferred = await screen.findByTestId('carrier-node-node-a');
    expect(within(preferred).getByTestId('carrier-default-node-indicator')).toHaveTextContent('全网默认');
    expect(within(screen.getByTestId('carrier-node-node-b')).queryByTestId('carrier-default-node-indicator')).not.toBeInTheDocument();
    expect(screen.getByText('carrierLegacyDefaultBinding')).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByLabelText('node-a carrierLine'));
    expect(screen.queryByRole('option', { name: '全网默认' })).not.toBeInTheDocument();
  });

  it('excludes the all-network default and keeps keyword AND search', async () => {
    const names = new Map([
      ['Yidong', '移动'],
      ['default', '全网默认'],
      ['Dianxin', '电信'],
      ['Liantong', '联通'],
      ['Dianxin_Shanghai', '电信_上海'],
      ['Liantong_Shanghai', '联通_上海'],
      ['Yidong_Shanghai', '移动_上海'],
      ['Yidong_Sichuan', '移动_四川'],
    ]);
    const options = buildCarrierLineOptions(names.keys(), names);
    expect(options.some((option) => option.value === 'default')).toBe(false);

    const labels = (query: string) => options
      .filter((option) => carrierLineMatchesSearch(query, option))
      .map((option) => option.label);
    expect(labels('电信')).toEqual(['电信', '电信_上海']);
    expect(labels('上海')).toHaveLength(3);
    expect(labels('上海')).toEqual(expect.arrayContaining(['电信_上海', '联通_上海', '移动_上海']));
    expect(labels('移动   四川')).toEqual(['移动_四川']);
    expect(labels('默认')).toEqual([]);
    expect(labels('全网')).toEqual([]);
    expect(labels('上海')).not.toContain('全网默认');
    expect(labels('DIANXIN')).toEqual(['电信', '电信_上海']);

    arrange();
    const input = await screen.findByLabelText('node-a carrierLine');
    fireEvent.mouseDown(input);
    fireEvent.change(input, { target: { value: '移动 四川' } });
    expect(await screen.findByText('移动_四川')).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: '全网默认' })).not.toBeInTheDocument();
  });

  it('moves the derived default indicator when preferred Relay telemetry changes', async () => {
    arrange({}, [
      { ...nodes[0], preferred: false },
      { ...nodes[1], preferred: true },
    ]);
    await screen.findByTestId('carrier-node-node-a');
    expect(within(screen.getByTestId('carrier-node-node-a')).queryByTestId('carrier-default-node-indicator')).not.toBeInTheDocument();
    expect(within(screen.getByTestId('carrier-node-node-b')).getByTestId('carrier-default-node-indicator')).toHaveTextContent('全网默认');
  });

  it('never includes a legacy default binding in the Carrier PUT payload', async () => {
    arrange();
    fireEvent.click(await screen.findByRole('button', { name: /carrierSave/ }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    expect(mockPut).toHaveBeenCalledWith('/groups/7/carrier-affinity', {
      bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }],
    });
  });

  it.each([
    ['DEFAULT_LINE_OWNED_BY_RELAY_PREFERENCE', '全网默认线路请使用“设为默认线路”功能管理'],
    ['FAILOVER_ENABLED', '已启用故障切换，无法应用运营商线路策略'],
    ['CATALOG_STALE', '运营商线路目录已过期，请稍后重试'],
    ['DNSMGR_UNAVAILABLE', 'DNS 服务暂不可用'],
    ['TRANSACTION_IN_PROGRESS', '当前有线路事务正在执行'],
    ['OWNERSHIP_UNVERIFIED', 'DNS 记录所有权无法确认'],
  ])('maps known backend error %s', (backendMessage, expected) => {
    expect(carrierApplyErrorMessage({ response: { data: { message: backendMessage } } }, t)).toBe(expected);
  });

  it('shows only bounded provider preflight detail and hides unknown internals', () => {
    expect(carrierApplyErrorMessage({ response: { data: { message: 'PROVIDER_PREFLIGHT: DNSMgr request timed out' } } }, t))
      .toBe('DNS 服务预检查失败: DNSMgr request timed out');
    expect(carrierApplyErrorMessage({ response: { data: { message: 'database password=secret' } } }, t))
      .toBe('运营商线路策略应用失败');
  });

  it('shows a useful known save error instead of the generic fallback', async () => {
    const errorSpy = vi.spyOn(message, 'error');
    arrange();
    mockPut.mockRejectedValueOnce({ response: { data: { message: 'DEFAULT_LINE_OWNED_BY_RELAY_PREFERENCE' } } });
    fireEvent.click(await screen.findByRole('button', { name: /carrierSave/ }));
    await waitFor(() => expect(errorSpy).toHaveBeenCalledWith('全网默认线路请使用“设为默认线路”功能管理'));
  });

  it('locks edits while the existing DNS transaction is active', async () => {
    arrange({ transaction: { kind: 'carrier_policy_apply', state: 'switching', started_at: 'now', last_error: null, rollback_error: null } });
    expect(await screen.findByText('carrierBusy')).toBeInTheDocument();
    expect(screen.getByLabelText('node-a carrierLine')).toBeDisabled();
  });
});
