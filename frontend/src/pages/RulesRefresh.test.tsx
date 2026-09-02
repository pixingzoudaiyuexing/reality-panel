import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet, refreshCurrentUser } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  refreshCurrentUser: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isAdmin: true,
    user: { id: 1 },
    refreshCurrentUser,
  }),
}));

vi.mock('react-router-dom', () => ({
  useSearchParams: () => [new URLSearchParams(), vi.fn()],
}));

import Rules from './Rules';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const flush = (ms = 0) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

const rule = {
  id: 1,
  name: 'alpha-rule',
  uid: 1,
  paused: false,
  listen_port: 443,
  protocol: 'tcp',
  public_transport: 'nginx_sni',
  node_transport: 'nginx_sni',
  route_mode: 'direct',
  device_group_in: 7,
  device_group_out: null,
  forward_mode: 'direct',
  tunnel_profile_id: null,
  sni: 'alpha.example.com',
  camouflage_enabled: false,
  send_proxy_protocol: false,
  target_addr: '198.51.100.10',
  target_port: 443,
  targets: [{ id: 1, rule_id: 1, host: '198.51.100.10', port: 443, position: 0, enabled: true, created_at: '' }],
  load_balance_strategy: 'first',
  upload_limit_mbps: 0,
  download_limit_mbps: 0,
  max_connections: 0,
  auto_restart_minutes: 0,
  config: '{}',
  traffic_used: 10,
  status: 'active',
  created_at: '',
};

const group = {
  id: 7,
  name: 'relay-group',
  group_type: 'in',
  uid: 1,
  connect_host: '',
  port_range: '10000-65535',
  fallback_group: null,
  config: '{}',
  rate: 1,
  created_at: '',
};

const dnsPropagated = {
  rule_id: 1,
  eligible: true,
  automation_enabled: true,
  fqdn: 'alpha.example.com',
  record_type: 'A',
  expected_value: '203.0.113.10',
  ownership: 'PANEL_MANAGED',
  sync_state: 'PROPAGATED',
  last_observed_at: null,
  mutation_verified_at: null,
  propagated_at: null,
  last_error_category: null,
  warning_category: null,
};

function initialResponse(url: string) {
  if (url === '/rules?owner_uid=1') return Promise.resolve(ok([rule]));
  if (url === '/groups') return Promise.resolve(ok([group]));
  if (url === '/admin/users') return Promise.resolve(ok([]));
  if (url === '/nodes') return Promise.resolve(ok([]));
  if (url === '/admin/rules/dns-status') return Promise.resolve(ok([dnsPropagated]));
  return Promise.reject(new Error(`unexpected ${url}`));
}

beforeEach(() => {
  vi.useFakeTimers();
  mockGet.mockReset();
  refreshCurrentUser.mockReset();
  mockGet.mockImplementation(initialResponse);
});

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

describe('Rules lightweight background refresh', () => {
  it('shows an inline retry when the initial rules request fails', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.reject(new Error('database unavailable'));
      return initialResponse(url);
    });
    render(<Rules />);
    await flush();
    expect(screen.getByText('rulesLoadFailed')).toBeInTheDocument();
    expect(screen.queryByText('rulesEmpty')).not.toBeInTheDocument();

    mockGet.mockImplementation(initialResponse);
    fireEvent.click(screen.getByRole('button', { name: 'retry' }));
    await flush();
    expect(screen.getByText('alpha-rule')).toBeInTheDocument();
    expect(screen.queryByText('rulesLoadFailed')).not.toBeInTheDocument();
  });

  it('distinguishes a valid empty rules list from a load failure', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.resolve(ok([]));
      return initialResponse(url);
    });
    render(<Rules />);
    await flush();
    expect(screen.getByText('rulesEmpty')).toBeInTheDocument();
    expect(screen.queryByText('rulesLoadFailed')).not.toBeInTheDocument();
  });

  it('treats a non-zero rules envelope as a load failure and recovers on retry', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.resolve({ code: 500, message: 'database unavailable', data: null });
      return initialResponse(url);
    });
    render(<Rules />);
    await flush();
    expect(screen.getByText('rulesLoadFailed')).toBeInTheDocument();
    expect(screen.queryByText('rulesEmpty')).not.toBeInTheDocument();

    mockGet.mockImplementation(initialResponse);
    fireEvent.click(screen.getByRole('button', { name: 'retry' }));
    await flush();
    expect(screen.getByText('alpha-rule')).toBeInTheDocument();
    expect(screen.queryByText('rulesLoadFailed')).not.toBeInTheDocument();
  });

  it('treats a non-zero groups envelope as a load failure, not a valid empty page', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url === '/groups') return Promise.resolve({ code: 500, message: 'groups unavailable', data: null });
      return initialResponse(url);
    });
    render(<Rules />);
    await flush();
    expect(screen.getByText('rulesLoadFailed')).toBeInTheDocument();
    expect(screen.queryByText('rulesEmpty')).not.toBeInTheDocument();
  });

  it('loads normally, then polls only dynamic admin endpoints after ten seconds', async () => {
    render(<Rules />);
    await flush();
    expect(screen.getByText('alpha-rule')).toBeInTheDocument();

    mockGet.mockClear();
    await flush(10000);

    expect(mockGet).toHaveBeenCalledWith('/rules?owner_uid=1');
    expect(mockGet).toHaveBeenCalledWith('/nodes');
    expect(mockGet).toHaveBeenCalledWith('/admin/rules/dns-status');
    expect(mockGet).not.toHaveBeenCalledWith('/groups');
    expect(mockGet).not.toHaveBeenCalledWith('/admin/users');
  });

  it('keeps old DNS state and visible filters when one background endpoint fails', async () => {
    render(<Rules />);
    await flush();
    expect(document.querySelector('.rp-compact-status')).toHaveTextContent('rulesStatusNormal');

    fireEvent.change(screen.getByPlaceholderText('searchRulePlaceholder'), {
      target: { value: 'alpha' },
    });
    fireEvent.mouseDown(screen.getByRole('combobox'));
    const groupOptions = screen.getAllByText('relay-group');
    fireEvent.click(groupOptions[groupOptions.length - 1]);

    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.resolve(ok([{ ...rule, traffic_used: 20 }]));
      if (url === '/nodes') return Promise.resolve(ok([]));
      if (url === '/admin/rules/dns-status') return Promise.reject(new Error('transient DNS failure'));
      return Promise.reject(new Error(`static endpoint was polled: ${url}`));
    });
    await flush(10000);

    expect(screen.getByPlaceholderText('searchRulePlaceholder')).toHaveValue('alpha');
    expect(screen.getByRole('combobox').closest('.ant-select')).toHaveTextContent('relay-group');
    expect(document.querySelector('.rp-compact-status')).toHaveTextContent('rulesStatusNormal');
    expect(screen.getByText('traffic 20 B')).toBeInTheDocument();
  });

  it('keeps old rules and reports a failed background rules refresh', async () => {
    render(<Rules />);
    await flush();
    expect(screen.getByText('alpha-rule')).toBeInTheDocument();

    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.reject(new Error('temporary rules failure'));
      if (url === '/nodes') return Promise.resolve(ok([]));
      if (url === '/admin/rules/dns-status') return Promise.resolve(ok([dnsPropagated]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    await flush(10000);

    expect(screen.getByText('alpha-rule')).toBeInTheDocument();
    expect(screen.getByText('rulesLoadFailed')).toBeInTheDocument();
    expect(screen.queryByText('rulesEmpty')).not.toBeInTheDocument();
  });

  it('does not show table loading or overlap ticks while a background refresh is slow', async () => {
    render(<Rules />);
    await flush();

    type RuleResponse = { code: number; message: string; data: typeof rule[] };
    type NodesResponse = { code: number; message: string; data: unknown[] };
    type DnsResponse = { code: number; message: string; data: typeof dnsPropagated[] };
    let resolveRules!: (value: RuleResponse) => void;
    let resolveNodes!: (value: NodesResponse) => void;
    let resolveDns!: (value: DnsResponse) => void;
    const slowRules = new Promise<RuleResponse>((resolve) => { resolveRules = resolve; });
    const slowNodes = new Promise<NodesResponse>((resolve) => { resolveNodes = resolve; });
    const slowDns = new Promise<DnsResponse>((resolve) => { resolveDns = resolve; });
    mockGet.mockReset();
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return slowRules;
      if (url === '/nodes') return slowNodes;
      if (url === '/admin/rules/dns-status') return slowDns;
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    await flush(10000);
    expect(document.querySelector('.ant-spin-spinning')).toBeNull();
    expect(mockGet).toHaveBeenCalledTimes(3);
    await flush(10000);
    expect(mockGet).toHaveBeenCalledTimes(3);

    resolveRules(ok([rule]));
    resolveNodes(ok([]));
    resolveDns(ok([dnsPropagated]));
    await flush();
  });

  it('preserves page, selection and an open edit modal during background refresh', async () => {
    const manyRules = Array.from({ length: 21 }, (_, index) => ({
      ...rule,
      id: index + 1,
      name: `rule-${index + 1}`,
      sni: `q${index + 1}.example.com`,
      targets: [{ ...rule.targets[0], id: index + 1, rule_id: index + 1 }],
    }));
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.resolve(ok(manyRules));
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/admin/users') return Promise.resolve(ok([]));
      if (url === '/nodes') return Promise.resolve(ok([]));
      if (url === '/admin/rules/dns-status') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    render(<Rules />);
    await flush();
    fireEvent.click(screen.getByTitle('2'));
    await flush();
    const section = screen.getByTestId('rules-group-7');
    const row = screen.getByText('rule-21').closest('tr') as HTMLElement;
    fireEvent.click(within(section).getAllByRole('checkbox')[1]);
    fireEvent.click(within(row).getByRole('button', { name: /edit/ }));
    expect(screen.getByText('editRule')).toBeInTheDocument();
    expect(screen.getByTestId('rules-batchbar')).toHaveAttribute('data-selected-count', '1');

    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.resolve(ok(manyRules.map(item => ({ ...item, traffic_used: 20 }))));
      if (url === '/nodes') return Promise.resolve(ok([]));
      if (url === '/admin/rules/dns-status') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`static endpoint was polled: ${url}`));
    });
    await flush(10000);

    expect(screen.getByTitle('2')).toHaveClass('ant-pagination-item-active');
    expect(screen.getByText('rule-21')).toBeInTheDocument();
    expect(screen.getByTestId('rules-batchbar')).toHaveAttribute('data-selected-count', '1');
    expect(screen.getByText('editRule')).toBeInTheDocument();
  });
});
