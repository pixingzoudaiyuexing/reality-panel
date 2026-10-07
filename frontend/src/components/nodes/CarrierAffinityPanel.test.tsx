import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CarrierAffinityView, CarrierLineCatalog, RelayReadyNode, RoutingApplyResult } from '../../api/types';
import type { Tfn } from './types';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));
vi.mock('../../api/client', () => ({ default: { get: mockGet } }));

import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { assignCarrierLines, buildCarrierLineOptions, carrierLineMatchesSearch } from './carrierCatalog';

const translations: Record<string, string> = {
  carrierAllNetworkDefault: '全网默认',
  carrierDefaultSelected: '✓ 全网默认',
  carrierSetDefault: '设为全网默认',
  carrierErrorDefaultAuthority: '全网默认线路请使用“设为默认线路”功能管理',
  carrierErrorFailoverEnabled: '已启用故障切换，无法应用运营商线路策略',
  carrierErrorCatalogStale: '运营商线路目录已过期，请稍后重试',
  carrierErrorDnsMgrUnavailable: 'DNS 服务暂不可用',
  carrierErrorTransactionInProgress: '当前有线路事务正在执行',
  carrierErrorOwnershipUnverified: 'DNS 记录所有权无法确认',
  carrierErrorProviderPreflight: 'DNS 服务预检查失败',
  carrierCatalogIncompatible: '发现不兼容的运营商分流规则，请调整',
  carrierCatalogActionable: '已定位到可调整的规则或 DNS Zone。',
  carrierCatalogAmbiguous: '这些规则对应的 DNS 线路目录没有共同可用线路。',
  carrierCatalogLineCount: '条线路',
  carrierNoEligibleRules: '当前没有可用于运营商分流的生效规则',
  carrierSaveFailed: '运营商线路策略应用失败',
  routingSaveAndActivate: '保存并启用',
  routingSaveChanges: '保存修改',
};
const t = ((key: string) => translations[key] ?? key) as Tfn;
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const nodes: RelayReadyNode[] = [
  { node_id: 'node-a', public_ipv4: '203.0.113.5', online: true, ready: true, ready_reasons: [], preferred: true },
  { node_id: 'node-b', public_ipv4: '203.0.113.6', online: false, ready: false, ready_reasons: ['CONTROL_CHANNEL_OFFLINE'], preferred: false },
];
const catalog: CarrierLineCatalog = {
  stale: false,
  issues: [],
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
  ], default_node_id: 'node-a' },
  pending_policy: null,
  transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
  bindings: [],
  catalog_stale: false,
};
const applied = (over: Partial<RoutingApplyResult> = {}): RoutingApplyResult => ({
  config_saved: true,
  activation_requested: true,
  activation_succeeded: false,
  active_mode: 'normal',
  target_mode: 'carrier',
  transition_state: 'switching',
  business_error_code: null,
  message: 'started',
  ...over,
});
const mockApply = vi.fn(async () => applied());

function arrange(over: Partial<CarrierAffinityView> = {}, displayedNodes = nodes, activeMode: 'normal' | 'carrier' = 'normal', catalogResponse: CarrierLineCatalog = catalog) {
  const response = { ...view, ...over };
  mockGet.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/carrier-lines') ? catalogResponse : response)));
  return render(<CarrierAffinityPanel groupId={7} nodes={displayedNodes} t={t} activeMode={activeMode} onApply={mockApply} />);
}

describe('CarrierAffinityPanel node-oriented editor', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
    mockApply.mockResolvedValue(applied());
  });

  it('shows every Relay and keeps an offline Relay editable', async () => {
    arrange();
    expect(await screen.findByTestId('carrier-node-node-a')).toHaveTextContent('203.0.113.5');
    expect(screen.getByTestId('carrier-node-node-b')).toHaveTextContent('offline');
    expect(screen.getByLabelText('node-b carrierLine')).toBeEnabled();
  });

  it('assigns the same line to another Relay without removing the first', () => {
    expect(assignCarrierLines(view.active_policy.bindings, 'node-a', ['default', 'Dianxin'], view.default_node_id)).toEqual([
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-a' },
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
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
    expect(within(preferred).getByTestId('carrier-default-node-indicator')).toHaveTextContent('✓ 全网默认');
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

  it('moves the default indicator from the Carrier draft rather than preferred telemetry', async () => {
    arrange({ active_policy: { ...view.active_policy, default_node_id: 'node-b' } });
    await screen.findByTestId('carrier-node-node-a');
    expect(within(screen.getByTestId('carrier-node-node-a')).queryByTestId('carrier-default-node-indicator')).not.toBeInTheDocument();
    expect(within(screen.getByTestId('carrier-node-node-b')).getByTestId('carrier-default-node-indicator')).toHaveTextContent('✓ 全网默认');
  });

  it('changes Carrier default only in the draft until Apply', async () => {
    arrange();
    const nodeB = await screen.findByTestId('carrier-node-node-b');
    fireEvent.click(within(nodeB).getByRole('button', { name: '设为全网默认' }));
    expect(within(nodeB).getByTestId('carrier-default-node-indicator')).toHaveTextContent('✓ 全网默认');
    expect(mockApply).not.toHaveBeenCalled();
  });

  it('never includes a legacy default binding in the routing Apply payload', async () => {
    arrange();
    fireEvent.click(await screen.findByRole('button', { name: /保存并启用/ }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledTimes(1));
    expect(mockApply).toHaveBeenCalledWith({
      mode: 'carrier',
      default_node_id: 'node-a',
      bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }],
    });
  });

  it('uses Save and activate while inactive and Save changes while active', async () => {
    const inactive = arrange();
    expect(await screen.findByRole('button', { name: /保存并启用/ })).toBeEnabled();
    inactive.unmount();
    mockGet.mockReset();
    arrange({ active_policy: {
      default_node_id: 'node-a',
      bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }],
    } }, nodes, 'carrier');
    expect(await screen.findByRole('button', { name: /保存修改/ })).toBeDisabled();
  });

  it('locks edits while the existing DNS transaction is active', async () => {
    arrange({ transaction: { kind: 'carrier_policy_apply', state: 'switching', started_at: 'now', last_error: null, rollback_error: null } });
    expect(await screen.findByText('carrierBusy')).toBeInTheDocument();
    expect(screen.getByLabelText('node-a carrierLine')).toBeDisabled();
  });

  it('renders a specific actionable Rule warning without changing Apply payload', async () => {
    arrange({}, nodes, 'normal', {
      ...catalog,
      lines: [{ id: 'default', name: '全网默认', parent: null }],
      issues: [{
        kind: 'incompatible_line_catalogs',
        reason: 'no_common_line_ids',
        actionable: { level: 'rule', rule_id: 15 },
        zones: [
          { domain_id: 10, zone: 'huawei.example', provider_type: 'huawei', line_count: 2, rules: [
            { rule_id: 14, name: '美国1', sni: 'a.huawei.example' },
            { rule_id: 16, name: '美国3', sni: 'b.huawei.example' },
          ] },
          { domain_id: 20, zone: 'cloudflare.example', provider_type: 'cloudflare', line_count: 1, rules: [
            { rule_id: 15, name: '美国2', sni: 'apan1.cloudflare.example' },
          ] },
        ],
      }],
    });
    expect(await screen.findByText('发现不兼容的运营商分流规则，请调整')).toBeInTheDocument();
    expect(screen.getByText(/Rule 15 · 美国2/)).toBeInTheDocument();
    expect(screen.getByText('apan1.cloudflare.example')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /保存并启用/ }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledWith({
      mode: 'carrier',
      default_node_id: 'node-a',
      bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }],
    }));
  });

  it('renders ambiguous and no-eligible catalog warnings separately', async () => {
    const ambiguous = arrange({}, nodes, 'normal', {
      ...catalog,
      issues: [{
        kind: 'incompatible_line_catalogs',
        reason: 'no_common_line_ids',
        actionable: null,
        zones: [
          { domain_id: 10, zone: 'a.example', provider_type: 'a', line_count: 1, rules: [{ rule_id: 1, name: 'A', sni: 'a.example' }] },
          { domain_id: 20, zone: 'b.example', provider_type: 'b', line_count: 1, rules: [{ rule_id: 2, name: 'B', sni: 'b.example' }] },
        ],
      }],
    });
    expect(await screen.findByText('这些规则对应的 DNS 线路目录没有共同可用线路。')).toBeInTheDocument();
    ambiguous.unmount();
    mockGet.mockReset();

    arrange({}, nodes, 'normal', { ...catalog, issues: [{ kind: 'no_eligible_rules' }] });
    expect(await screen.findByText('当前没有可用于运营商分流的生效规则')).toBeInTheDocument();
  });
});


describe('Carrier authoritative progress and refresh', () => {
  beforeEach(() => { sessionStorage.clear(); vi.clearAllMocks(); mockApply.mockResolvedValue(applied()); });
  it('restores a running transaction on mount and disables mutation', async () => {
    arrange({ pending_policy: view.active_policy, transaction: { ...view.transaction, kind: 'carrier_policy_apply', state: 'switching' } }, nodes, 'carrier');
    expect(await screen.findByTestId('carrier-operation')).toHaveTextContent('carrierOperationSyncing');
    expect(screen.getByText('保存修改').closest('button')).toBeDisabled();
    expect(mockApply).not.toHaveBeenCalled();
  });
  it('keeps rollback error visible after page refresh', async () => {
    arrange({ transaction: { ...view.transaction, state: 'failed_manual_intervention', last_error: 'DNSMGR_TIMEOUT', rollback_error: 'POST_WRITE_NOT_VERIFIED' } }, nodes, 'carrier');
    expect(await screen.findByTestId('carrier-operation')).toHaveTextContent('POST_WRITE_NOT_VERIFIED');
    expect(screen.getByTestId('carrier-operation')).toHaveTextContent('carrierOperationRollbackFailed');
  });
  it('does not display completion merely because apply returns HTTP-success', async () => {
    arrange({ pending_policy: view.active_policy, transaction: { ...view.transaction, state: 'switching' } }, nodes, 'carrier');
    expect(await screen.findByTestId('carrier-operation')).not.toHaveTextContent('carrierOperationReady');
  });
  it('restores an uncertain submission without resubmitting', async () => {
    sessionStorage.setItem('reality-carrier-operation:7', JSON.stringify({ desired: { default_node_id: 'node-b', bindings: [] }, unknown: true, error: null }));
    arrange({}, nodes, 'carrier');
    expect(await screen.findByTestId('carrier-operation')).toHaveTextContent('carrierOperationUnknown');
    expect(screen.getByText('保存修改').closest('button')).toBeDisabled();
    expect(mockApply).not.toHaveBeenCalled();
  });
  it('keeps authoritative failure visible when Provider catalog reads fail', async () => {
    mockGet.mockImplementation((url: string) => url.endsWith('/carrier-lines') ? Promise.reject(new Error('Provider down')) : Promise.resolve(ok({ ...view, transaction: { ...view.transaction, state: 'failed_rolled_back', last_error: 'DNSMGR_TIMEOUT' } })));
    render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} activeMode="carrier" onApply={mockApply} />);
    expect(await screen.findByTestId('carrier-operation')).toHaveTextContent('DNSMGR_TIMEOUT');
    expect(screen.getByTestId('carrier-operation')).toHaveTextContent('carrierOperationRolledBack');
  });

  it('recovers a lost response through reads without a second apply', async () => {
    mockApply.mockRejectedValueOnce(new Error('response lost'));
    arrange({}, nodes, 'carrier');
    fireEvent.click(await screen.findByRole('button', { name: '设为全网默认' }));
    fireEvent.click(screen.getByRole('button', { name: /保存修改/ }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledTimes(1));
    expect(await screen.findByTestId('carrier-operation')).toHaveTextContent('carrierOperationUnknown');
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/carrier-lines') ? catalog : { ...view, active_policy: { default_node_id: 'node-b', bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }] } })));
    fireEvent.click(screen.getByRole('button', { name: 'carrierOperationRefresh' }));
    await waitFor(() => expect(JSON.parse(sessionStorage.getItem('reality-carrier-operation:7')!).desired).toBeNull());
    expect(screen.queryByText('carrierOperationUnknown')).not.toBeInTheDocument();
    expect(mockApply).toHaveBeenCalledTimes(1);
  });
  it('does not use the old same-policy success to resolve an interrupted request', async () => {
    const policy = { default_node_id: 'node-a', bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }] };
    sessionStorage.setItem('reality-carrier-operation:7', JSON.stringify({ desired: policy, pending: true, baseline: JSON.stringify(policy), observed: false }));
    arrange({}, nodes, 'carrier');
    expect(await screen.findByTestId('carrier-operation')).toHaveTextContent('carrierOperationUnknown');
    expect(mockApply).not.toHaveBeenCalled();
  });

  it('resolves a lost same-policy activation when the server confirms Carrier became active', async () => {
    const policy = { default_node_id: 'node-a', bindings: [{ line_id: 'Dianxin', mode: 'node', node_id: 'node-b' }] };
    sessionStorage.setItem('reality-carrier-operation:7', JSON.stringify({ desired: policy, unknown: true, baseline: JSON.stringify(policy), baselineMode: 'normal', observed: false }));
    arrange({}, nodes, 'carrier');
    await waitFor(() => expect(JSON.parse(sessionStorage.getItem('reality-carrier-operation:7')!).desired).toBeNull());
    expect(screen.queryByText('carrierOperationUnknown')).not.toBeInTheDocument();
    expect(mockApply).not.toHaveBeenCalled();
  });

});


describe('Carrier stale historical intent', () => {
  beforeEach(() => { sessionStorage.clear(); vi.clearAllMocks(); mockApply.mockResolvedValue(applied()); });
  const key = 'reality-carrier-operation:7';
  const stale = { desired: { default_node_id: 'node-b', bindings: [] }, unknown: false, pending: false, observed: true, error: null };

  it('clears the observed Production intent with different desired/active, including hard reload', async () => {
    sessionStorage.setItem(key, JSON.stringify(stale));
    const terminalDns = Array.from({ length: 24 }, (_, i) => ({ rule_id: i + 1, fqdn: `rp-test-${i}.example`, line_id: 'default', provider: 'huawei', state: 'PROPAGATED', last_error: null }));
    const page = arrange({ dns_records: terminalDns }, nodes, 'carrier');
    await waitFor(() => expect(JSON.parse(sessionStorage.getItem(key)!).desired).toBeNull());
    expect(screen.queryByText('carrierOperationUnknown')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'node-a carrierLine' })).not.toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: '设为全网默认' }));
    expect(screen.getByText('保存修改').closest('button')).toBeEnabled();
    page.unmount();
    arrange({}, nodes, 'carrier');
    await screen.findByRole('combobox', { name: 'node-a carrierLine' });
    expect(screen.queryByText('carrierOperationUnknown')).not.toBeInTheDocument();
    expect(mockApply).not.toHaveBeenCalled();
  });

  it.each(['PENDING', 'SYNCING', 'FAILED', 'MUTATION_OUTCOME_UNKNOWN'])('does not clear %s DNS', async (state) => {
    sessionStorage.setItem(key, JSON.stringify(stale));
    arrange({ dns_records: [{ rule_id: 1, fqdn: 'test.example', line_id: 'default', provider: 'huawei', state, last_error: null }] }, nodes, 'carrier');
    await screen.findByTestId('carrier-operation');
    expect(JSON.parse(sessionStorage.getItem(key)!).desired).not.toBeNull();
    expect(mockApply).not.toHaveBeenCalled();
  });

  it('does not clear historical intent on failed authoritative GET', async () => {
    sessionStorage.setItem(key, JSON.stringify(stale));
    mockGet.mockRejectedValue(new Error('read unavailable'));
    render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} activeMode="carrier" onApply={mockApply} />);
    await screen.findByText('carrierLoadFailed');
    expect(JSON.parse(sessionStorage.getItem(key)!).desired).not.toBeNull();
  });

  it.each(['switching' , 'rolling_back', 'failed_manual_intervention'] as const)('preserves protection for %s', async (state) => {
    sessionStorage.setItem(key, JSON.stringify(stale));
    arrange({ transaction: { ...view.transaction, state } }, nodes, 'carrier');
    await screen.findByTestId('carrier-operation');
    expect(JSON.parse(sessionStorage.getItem(key)!).desired).not.toBeNull();
    expect(screen.getByRole('combobox', { name: 'node-a carrierLine' })).toBeDisabled();
  });
});


describe('Carrier new mutation read ordering', () => {
  beforeEach(() => { sessionStorage.clear(); vi.clearAllMocks(); mockApply.mockResolvedValue(applied()); });
  afterEach(() => { vi.useRealTimers(); });

  it('keeps a lost response protected through server takeover then clears terminal differing intent', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    mockApply.mockRejectedValueOnce(new Error('lost response'));
    let current = view;
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/carrier-lines') ? catalog : current)));
    render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} activeMode="carrier" onApply={mockApply} />);
    await screen.findByText('✓ 全网默认');
    fireEvent.click(screen.getByRole('button', { name: '设为全网默认' }));
    fireEvent.click(screen.getByText('保存修改'));
    expect(await screen.findByText('carrierOperationUnknown')).toBeInTheDocument();
    expect(JSON.parse(sessionStorage.getItem('reality-carrier-operation:7')!).observed).toBe(false);
    expect(screen.getByRole('combobox', { name: 'node-a carrierLine' })).toBeDisabled();
    current = { ...view, pending_policy: { default_node_id: 'node-b', bindings: [] }, transaction: { ...view.transaction, state: 'switching' } };
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(screen.getByText('carrierOperationSyncing')).toBeInTheDocument();
    expect(JSON.parse(sessionStorage.getItem('reality-carrier-operation:7')!).observed).toBe(true);
    current = view;
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    await waitFor(() => expect(JSON.parse(sessionStorage.getItem('reality-carrier-operation:7')!).desired).toBeNull());
    expect(screen.getByRole('combobox', { name: 'node-a carrierLine' })).not.toBeDisabled();
    const reads = mockGet.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(mockGet).toHaveBeenCalledTimes(reads);
    expect(mockApply).toHaveBeenCalledTimes(1);
  });

  it('discards a GET from before a POST and cannot mark takeover from that old response', async () => {
    let release: (value: ReturnType<typeof ok<CarrierAffinityView>>) => void = () => {};
    let slow = false;
    mockGet.mockImplementation((url: string) => url.endsWith('/carrier-lines') ? Promise.resolve(ok(catalog))
      : slow ? new Promise((resolve) => { release = resolve; }) : Promise.resolve(ok(view)));
    const page = render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} activeMode="carrier" onApply={mockApply} />);
    await screen.findByText('✓ 全网默认');
    slow = true;
    page.rerender(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} activeMode="carrier" onApply={mockApply} onViewChange={() => {}} />);
    fireEvent.click(screen.getByRole('button', { name: '设为全网默认' }));
    mockApply.mockRejectedValueOnce(new Error('lost response'));
    fireEvent.click(screen.getByText('保存修改'));
    await waitFor(() => expect(mockApply).toHaveBeenCalledTimes(1));
    slow = false;
    await act(async () => { release(ok({ ...view, pending_policy: view.active_policy, transaction: { ...view.transaction, state: 'switching' } })); });
    await waitFor(() => expect(screen.getByText('carrierOperationUnknown')).toBeInTheDocument());
    expect(JSON.parse(sessionStorage.getItem('reality-carrier-operation:7')!).observed).toBe(false);
    expect(screen.getByRole('combobox', { name: 'node-a carrierLine' })).toBeDisabled();
  });
});
