import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet, mockPost, mockPut, mockDelete, refreshCurrentUser, mockUseAuth } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockPut: vi.fn(),
  mockDelete: vi.fn(),
  refreshCurrentUser: vi.fn(),
  mockUseAuth: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, post: mockPost, put: mockPut, delete: mockDelete },
}));
vi.mock('../auth/useAuth', () => ({ useAuth: mockUseAuth }));
vi.mock('react-router-dom', () => ({ useSearchParams: () => [new URLSearchParams(), vi.fn()] }));

import Rules, { RULE_SELECTION_COLUMN_WIDTH, RULE_TABLE_SCROLL_X, RULES_PAGE_SIZE } from './Rules';
import { zhCN } from '../i18n/zh-CN';
import { enUS } from '../i18n/en-US';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const group = (id: number, name: string, connect_host = '') => ({
  id, name, group_type: 'in', uid: 1, connect_host, port_range: '10000-65535',
  fallback_group: null, config: '{}', rate: 1, created_at: '',
});
const rule = (id: number, overrides: Record<string, unknown> = {}) => ({
  id, name: `rule-${id}`, uid: 1, paused: false, listen_port: 443, protocol: 'tcp',
  public_transport: 'nginx_sni', node_transport: 'nginx_sni', route_mode: 'direct',
  device_group_in: 7, device_group_out: null, forward_mode: 'direct', tunnel_profile_id: null,
  sni: `q${id}.example.com`, camouflage_enabled: true, send_proxy_protocol: false,
  target_addr: '198.51.100.10', target_port: 55443,
  targets: [{ id, rule_id: id, host: '198.51.100.10', port: 55443, position: 0, enabled: true, created_at: '' }],
  load_balance_strategy: 'first', upload_limit_mbps: 0, download_limit_mbps: 0,
  max_connections: 0, auto_restart_minutes: 0, config: '{}', traffic_used: 0,
  status: 'active', created_at: '', ...overrides,
});
const dnsStatus = (ruleId: number) => ({
  rule_id: ruleId, eligible: true, automation_enabled: true, fqdn: `q${ruleId}.example.com`,
  record_type: 'A', expected_value: '203.0.113.10', ownership: 'PANEL_MANAGED',
  sync_state: 'PROPAGATED', last_observed_at: null, mutation_verified_at: null,
  propagated_at: null, last_error_category: null, warning_category: null,
});

function setupAdmin(
  rules = [rule(1)],
  groups = [group(7, 'relay-group', '203.0.113.10')],
  users = [{ id: 1, username: 'admin', traffic_limit: 0, traffic_used: 0 }],
) {
  mockUseAuth.mockReturnValue({ isAdmin: true, user: { id: 1 }, refreshCurrentUser });
  mockGet.mockImplementation((url: string) => {
    if (url === '/rules?owner_uid=1') return Promise.resolve(ok(rules));
    if (url === '/groups') return Promise.resolve(ok(groups));
    if (url === '/admin/users') return Promise.resolve(ok(users));
    if (url === '/nodes') return Promise.resolve(ok([]));
    if (url === '/admin/rules/dns-status') return Promise.resolve(ok(rules.map(item => dnsStatus(item.id))));
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

function setupUser(rules = [rule(1)], groups = [group(7, 'shared-group', '203.0.113.10')]) {
  mockUseAuth.mockReturnValue({ isAdmin: false, user: { id: 2 }, refreshCurrentUser });
  mockGet.mockImplementation((url: string) => {
    if (url === '/rules') return Promise.resolve(ok(rules));
    if (url === '/groups') return Promise.resolve(ok([]));
    if (url === '/groups/shared') return Promise.resolve(ok(groups));
    if (url === '/user/me') return Promise.resolve(ok({ traffic_used: 0, traffic_limit: 0 }));
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockPut.mockReset();
  mockDelete.mockReset();
  refreshCurrentUser.mockReset();
  mockPost.mockResolvedValue(ok({ applied: 1, restarted: 1, nodes: [] }));
  mockPut.mockResolvedValue(ok(null));
  mockDelete.mockResolvedValue(ok(null));
  setupAdmin();
});

describe('Rules grouped compact layout', () => {
  const visibleRuleEditor = () => Array.from(document.querySelectorAll<HTMLElement>('.rp-rule-editor-modal'))
    .find((modal) => modal.style.display !== 'none') ?? null;

  async function openCreateRuleEditor() {
    fireEvent.click(screen.getByRole('button', { name: /addRule/ }));
    await waitFor(() => expect(visibleRuleEditor()).not.toBeNull());
    return visibleRuleEditor() as HTMLElement;
  }

  async function openCreateCopyEditor(reality = true) {
    const row = (await screen.findByText('rule-1')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: /moreActions/ }));
    fireEvent.click(await screen.findByText('copy'));
    await waitFor(() => {
      const modal = visibleRuleEditor() as HTMLElement;
      if (reality) {
        expect(within(modal).getByLabelText('sni')).toBeInTheDocument();
        expect(within(modal).getByText(/ruleReality(?:Runtime|Protocol)Summary/)).toBeInTheDocument();
      } else {
        expect(within(modal).getByLabelText('protocol')).toBeInTheDocument();
      }
    });
    return visibleRuleEditor() as HTMLElement;
  }

  async function openExistingRuleEditor() {
    const row = (await screen.findByText('rule-1')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: /edit/ }));
    const title = await screen.findByText('editRule');
    return title.closest('[role="dialog"]') as HTMLElement;
  }

  async function openRuleEditor() {
    render(<Rules />);
    return openExistingRuleEditor();
  }

  it('keeps page actions in the header and search/filter in a separate toolbar', async () => {
    render(<Rules />);
    const header = screen.getByText('forwardRules').closest('.rp-page-header');
    const toolbar = await screen.findByTestId('rules-toolbar');
    expect(header).toContainElement(screen.getByRole('button', { name: /refresh/ }));
    expect(header).toContainElement(screen.getByRole('button', { name: /exportImport/ }));
    expect(header).toContainElement(screen.getByRole('button', { name: /addRule/ }));
    expect(toolbar).toContainElement(screen.getByPlaceholderText('searchRulePlaceholder'));
    expect(toolbar).toContainElement(screen.getByRole('combobox'));
  });

  it('uses six compact columns plus selection and no group-name column', async () => {
    render(<Rules />);
    await screen.findByText('rule-1');
    expect(screen.queryByRole('columnheader', { name: 'groupName' })).toBeNull();
    for (const title of ['ruleColumn', 'ruleEntry', 'protocolForward', 'target', 'status', 'action']) {
      expect(screen.getByRole('columnheader', { name: title })).toBeInTheDocument();
    }
    expect(screen.getByRole('columnheader', { name: 'action' })).toHaveClass('ant-table-cell-fix-end');
    expect(RULE_SELECTION_COLUMN_WIDTH).toBe(48);
    expect(RULE_TABLE_SCROLL_X).toBe(1320);
    expect(RULES_PAGE_SIZE).toBe(20);
  });

  it('groups the current page and shows filtered totals in lightweight headers', async () => {
    setupAdmin([rule(1), rule(2), rule(3, { device_group_in: 8 })], [group(7, 'tokyo'), group(8, 'osaka')]);
    render(<Rules />);
    const tokyo = await screen.findByTestId('rules-group-7');
    const osaka = screen.getByTestId('rules-group-8');
    expect(within(tokyo).getByText('tokyo')).toBeInTheDocument();
    expect(within(tokyo).getByText('ruleCount')).toBeInTheDocument();
    expect(within(osaka).getByText('osaka')).toBeInTheDocument();
    expect(within(osaka).getByText('ruleCount')).toBeInTheDocument();
  });

  it('formats group counts naturally in Chinese and English', () => {
    expect(zhCN.ruleCount.replace('{count}', '2')).toBe('2 条规则');
    expect(enUS.ruleCount.replace('{count}', '2')).toBe('2 rules');
  });

  it('shows name, id and owner for admins but hides owner metadata from users', async () => {
    const first = render(<Rules />);
    expect(await screen.findByText('rule-1')).toHaveClass('rp-rules-ellipsis');
    expect(screen.getByText('#1 · admin')).toBeInTheDocument();
    first.unmount();
    setupUser();
    render(<Rules />);
    await screen.findByText('rule-1');
    expect(screen.getByText('#1')).toBeInTheDocument();
    expect(screen.queryByText('#1 · admin')).toBeNull();
  });

  it('uses SNI for Reality entries and safe port-only fallbacks when identity is absent', async () => {
    setupAdmin([
      rule(1),
      rule(2, { sni: null }),
      rule(3, { public_transport: 'raw', node_transport: 'raw', sni: null, listen_port: 12345 }),
      rule(4, { public_transport: 'raw', node_transport: 'raw', sni: null, listen_port: 23456, device_group_in: 8 }),
    ], [group(7, 'with-host', '203.0.113.10'), group(8, 'without-host')]);
    render(<Rules />);
    expect(await screen.findByText('q1.example.com:443')).toBeInTheDocument();
    expect(screen.getByText('port 443')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.10:12345')).toBeInTheDocument();
    expect(screen.getByText('port 23456')).toBeInTheDocument();
    expect(screen.queryByText('203.0.113.10:443')).toBeNull();
  });

  it('preserves protocol, target pool, strategy and dense Reality status information', async () => {
    setupAdmin([
      rule(1, {
        paused: true,
        load_balance_strategy: 'failover',
        traffic_used: 145,
        targets: [
          { host: '198.51.100.10', port: 55443, enabled: true },
          { host: '198.51.100.20', port: 55443, enabled: true },
        ],
      }),
      rule(2),
    ], undefined, [{ id: 1, username: 'admin', traffic_limit: 100, traffic_used: 100 }]);
    render(<Rules />);
    const row = (await screen.findByText('rule-1')).closest('tr') as HTMLElement;
    expect(within(row).getByText('TCP')).toBeInTheDocument();
    expect(within(row).getByText('entryTransportNginxSni')).toBeInTheDocument();
    expect(within(row).getByText('198.51.100.10:55443 (+1)')).toBeInTheDocument();
    expect(within(row).getByText('lbFailover')).toBeInTheDocument();
    expect(within(row).getByText('dns')).toBeInTheDocument();
    expect(within(row).getByText('routeDetails')).toBeInTheDocument();
    expect(within(row).getByText('certificateDetails')).toBeInTheDocument();
    const statusTrigger = row.querySelector('.rp-rules-status-cell .rp-compact-status') as HTMLElement;
    expect(statusTrigger).toBeInTheDocument();
    expect(statusTrigger.querySelectorAll(':scope > span')).toHaveLength(2);
    expect(statusTrigger).not.toHaveTextContent('PROPAGATED');
    expect(statusTrigger.querySelector('[data-raw-state="PROPAGATED"]')).toBeInTheDocument();
    expect(within(row).getByText('traffic 145 B')).toBeInTheDocument();
    expect(within(row).getByText('paused')).toBeInTheDocument();
    expect(within(row).getByText('traffic 145 B')).toBeInTheDocument();
    expect(row.querySelector('.rp-rules-protocol-cell')).not.toHaveTextContent('paused');
    expect(within(row).getByText('198.51.100.10:55443 (+1)').closest('.rp-rules-target-tooltip'))
      .toHaveAttribute('data-target-pool', '198.51.100.10:55443,198.51.100.20:55443');

    const quotaRow = screen.getByText('rule-2').closest('tr') as HTMLElement;
    expect(quotaRow.querySelector('.rp-rules-status-cell')).toHaveTextContent('quotaExhausted');
    expect(quotaRow.querySelector('.rp-rules-protocol-cell')).not.toHaveTextContent('quotaExhausted');
  });

  it('keeps only edit, diagnose and more persistent while preserving Reality and raw menu actions', async () => {
    setupAdmin([rule(1), rule(2, { public_transport: 'raw', node_transport: 'raw', sni: null })]);
    render(<Rules />);
    const row = (await screen.findByText('rule-1')).closest('tr') as HTMLElement;
    const actions = row.querySelector('.rp-rules-actions') as HTMLElement;
    expect(within(actions).getAllByRole('button')).toHaveLength(3);
    expect(within(actions).getByRole('button', { name: /edit/ })).toBeInTheDocument();
    expect(within(actions).getByRole('button', { name: /diagnose/ })).toBeInTheDocument();
    fireEvent.click(within(actions).getByRole('button', { name: /moreActions/ }));
    expect(await screen.findByText('pause')).toBeInTheDocument();
    expect(screen.getByText('copy')).toBeInTheDocument();
    expect(screen.getByText('reapply')).toBeInTheDocument();
    expect(screen.getByText('delete')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });

    const rawRow = screen.getByText('rule-2').closest('tr') as HTMLElement;
    fireEvent.click(within(rawRow).getByRole('button', { name: /moreActions/ }));
    expect(await screen.findByText('restart')).toBeInTheDocument();
  });

  it('keeps UDP diagnosis disabled and requires confirmation for runtime actions', async () => {
    setupAdmin([
      rule(1, { protocol: 'udp', public_transport: 'raw', node_transport: 'raw' }),
      rule(2),
      rule(3, { public_transport: 'raw', node_transport: 'raw', sni: null }),
    ]);
    render(<Rules />);
    const udpRow = (await screen.findByText('rule-1')).closest('tr') as HTMLElement;
    expect(within(udpRow).getByRole('button', { name: /diagnose/ })).toBeDisabled();
    const realityRow = screen.getByText('rule-2').closest('tr') as HTMLElement;
    fireEvent.click(within(realityRow).getByRole('button', { name: /moreActions/ }));
    fireEvent.click(await screen.findByText('reapply'));
    expect((await screen.findAllByText('reapplyConfirmTitle')).length).toBeGreaterThan(0);
    expect(mockPost).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'reapply' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/rules/2/reapply', {}));

    const rawRow = screen.getByText('rule-3').closest('tr') as HTMLElement;
    fireEvent.click(within(rawRow).getByRole('button', { name: /moreActions/ }));
    fireEvent.click(await screen.findByText('restart'));
    expect((await screen.findAllByText('restartConfirmTitle')).length).toBeGreaterThan(0);
    expect(mockPost).not.toHaveBeenCalledWith('/rules/3/restart', {});
    fireEvent.click(screen.getByRole('button', { name: 'restart' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/rules/3/restart', {}));

  });

  it('aligns Create and Edit editor shells, tabs, field order, and advanced structure', async () => {
    render(<Rules />);
    await screen.findByText('rule-1');
    const create = await openCreateRuleEditor();
    expect(create).toHaveClass('rp-rule-editor-modal');
    expect(within(create).getByRole('tab', { name: 'tabBasic' })).toBeInTheDocument();
    expect(within(create).getByRole('tab', { name: 'tabForward' })).toBeInTheDocument();
    const createLabels = Array.from(create.querySelectorAll('.ant-tabs-tabpane-active .ant-form-item-label'))
      .map((label) => label.textContent?.trim());
    expect(createLabels.slice(0, 4)).toEqual(['name', 'inboundGroup', 'transportMethod', 'listenPort']);
    fireEvent.click(within(create).getByRole('button', { name: 'cancel' }));
    await waitFor(() => expect(visibleRuleEditor()).toBeNull());

    const realityCreate = await openCreateCopyEditor();
    expect(within(realityCreate).getByText(/ruleReality(?:Runtime|Protocol)Summary/)).toBeInTheDocument();
    expect(within(realityCreate).getByText('ruleAdvancedSettings · ruleAdvancedNone')).toBeInTheDocument();
    fireEvent.click(within(realityCreate).getByRole('button', { name: 'cancel' }));
    await waitFor(() => expect(visibleRuleEditor()).toBeNull());

    const edit = await openExistingRuleEditor();
    expect(edit).toHaveClass('rp-rule-editor-modal');
    const editLabels = Array.from(edit.querySelectorAll('.ant-tabs-tabpane-active .ant-form-item-label'))
      .map((label) => label.textContent?.trim());
    expect(editLabels.slice(0, 4)).toEqual(['name', 'inboundGroup', 'transportMethod', 'listenPort']);
    expect(within(edit).getByText('ruleRealityRuntimeSummary')).toBeInTheDocument();
    expect(within(edit).getByText('ruleAdvancedSettings · ruleAdvancedNone')).toBeInTheDocument();
  });

  it('creates Reality with unchanged defaults while omitting edit-only and display-only fields', async () => {
    setupAdmin([rule(1, { camouflage_enabled: false, send_proxy_protocol: false })]);
    render(<Rules />);
    const dialog = await openCreateCopyEditor();
    fireEvent.change(within(dialog).getByLabelText('name'), { target: { value: 'new-reality' } });
    fireEvent.change(within(dialog).getByLabelText('sni'), { target: { value: 'new.example.com' } });
    expect(within(dialog).queryByLabelText('protocol')).toBeNull();
    fireEvent.click(within(dialog).getByRole('button', { name: 'create' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/rules', expect.objectContaining({
      name: 'new-reality', protocol: 'tcp', public_transport: 'nginx_sni',
      camouflage_enabled: false, send_proxy_protocol: false,
      load_balance_strategy: 'first', upload_limit_mbps: 0, download_limit_mbps: 0,
    })));
    const payload = mockPost.mock.calls.find(([url]) => url === '/rules')?.[1] as Record<string, unknown>;
    expect(payload).not.toHaveProperty('max_connections');
    expect(payload).not.toHaveProperty('auto_restart_minutes');
    expect(payload).not.toHaveProperty('camouflage_tls_port');
    expect(payload).not.toHaveProperty('certificate_renew_before');
  });

  it('preserves Reality camouflage and Proxy Protocol through the Create payload', async () => {
    setupAdmin([rule(1, { camouflage_enabled: false, send_proxy_protocol: false })]);
    render(<Rules />);
    const dialog = await openCreateCopyEditor();
    fireEvent.change(within(dialog).getByLabelText('name'), { target: { value: 'new-proxy' } });
    fireEvent.change(within(dialog).getByLabelText('sni'), { target: { value: 'proxy.example.com' } });
    fireEvent.click(within(dialog).getByLabelText('camouflage'));
    fireEvent.click(within(dialog).getByText(/ruleAdvancedSettings/));
    fireEvent.click(within(dialog).getByLabelText('sendProxyProtocol'));
    await waitFor(() => expect(within(dialog).getByText('ruleAdvancedSettings · ruleAdvancedProxyEnabled')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'create' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/rules', expect.objectContaining({
      camouflage_enabled: true, send_proxy_protocol: true,
    })));
  });

  it('keeps Raw protocol, multi-target strategy, and collapsed rate-limit values in Create', async () => {
    setupAdmin([rule(1, {
      public_transport: 'raw', node_transport: 'raw', sni: null, protocol: 'tcp_udp',
      targets: [
        { id: 1, rule_id: 1, host: '198.51.100.20', port: 443, position: 0, enabled: true, created_at: '' },
        { id: 2, rule_id: 1, host: '198.51.100.21', port: 8443, position: 1, enabled: true, created_at: '' },
      ],
      upload_limit_mbps: 20, download_limit_mbps: 80,
    })]);
    render(<Rules />);
    const dialog = await openCreateCopyEditor(false);
    fireEvent.change(within(dialog).getByLabelText('name'), { target: { value: 'new-raw' } });
    expect(within(dialog).getByLabelText('protocol')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('tab', { name: 'tabForward' }));
    await waitFor(() => expect(within(dialog).getByLabelText('loadBalanceStrategy')).toBeInTheDocument());
    expect(within(dialog).getByText('ruleForwardAdvancedSettings · ruleAdvancedConfiguredCount')).toBeInTheDocument();
    const advanced = within(dialog).getByText(/ruleForwardAdvancedSettings/);
    fireEvent.click(advanced);
    const rateInputs = within(dialog).getAllByRole('spinbutton').slice(-2);
    expect(rateInputs[0]).toHaveValue('20');
    expect(rateInputs[1]).toHaveValue('80');
    fireEvent.click(advanced);
    fireEvent.click(advanced);
    expect(within(dialog).getAllByRole('spinbutton').slice(-2)[0]).toHaveValue('20');
    expect(within(dialog).getAllByRole('spinbutton').slice(-2)[1]).toHaveValue('80');
    fireEvent.click(within(dialog).getByRole('button', { name: 'create' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/rules', expect.objectContaining({
      protocol: 'tcp_udp', public_transport: 'raw', load_balance_strategy: 'first',
      upload_limit_mbps: 20, download_limit_mbps: 80,
    })));
    const payload = mockPost.mock.calls.find(([url]) => url === '/rules')?.[1] as Record<string, unknown>;
    expect(payload).not.toHaveProperty('max_connections');
    expect(payload).not.toHaveProperty('auto_restart_minutes');
  });

  it('requires explicit confirmation before deleting from the more menu', async () => {
    render(<Rules />);
    const row = (await screen.findByText('rule-1')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: /moreActions/ }));
    fireEvent.click(await screen.findByText('delete'));
    expect((await screen.findAllByText('deleteRuleConfirm')).length).toBeGreaterThan(0);
    expect(mockDelete).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'delete' }));
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/rules/1'));
  });

  it('keeps camouflage enabled when advanced settings stay collapsed', async () => {
    setupAdmin([rule(1, { camouflage_enabled: true })]);
    const dialog = await openRuleEditor();
    expect(await within(dialog).findByText('ruleRealityRuntimeSummary')).toBeInTheDocument();
    expect(within(dialog).queryByLabelText('camouflageTlsPort')).toBeNull();
    expect(within(dialog).queryByLabelText('certificateRenewBefore')).toBeNull();
    expect(within(dialog).getByText('ruleAdvancedSettings · ruleAdvancedNone')).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'editRule' })).toBeNull());
    expect(mockPut).not.toHaveBeenCalled();

    const reopened = await openExistingRuleEditor();
    fireEvent.change(within(reopened).getByLabelText('name'), { target: { value: 'renamed-rule' } });
    fireEvent.click(within(reopened).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/rules/1', { name: 'renamed-rule' }));
    const payload = mockPut.mock.calls.at(-1)?.[1] as Record<string, unknown>;
    expect(payload).not.toHaveProperty('camouflage_enabled');
    expect(payload).not.toHaveProperty('camouflage_tls_port');
    expect(payload).not.toHaveProperty('certificate_renew_before');
  });

  it('preserves an enabled Proxy Protocol without opening its collapse', async () => {
    setupAdmin([rule(1, { send_proxy_protocol: true })]);
    const dialog = await openRuleEditor();
    expect(await within(dialog).findByText('ruleAdvancedSettings · ruleAdvancedProxyEnabled')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'editRule' })).toBeNull());
    expect(mockPut).not.toHaveBeenCalled();

    const reopened = await openExistingRuleEditor();
    fireEvent.change(within(reopened).getByLabelText('listenPort'), { target: { value: '444' } });
    fireEvent.click(within(reopened).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/rules/1', { listen_port: 444 }));
    expect(mockPut.mock.calls.at(-1)?.[1]).not.toHaveProperty('send_proxy_protocol');
  });

  it('preserves every forwarding advanced value without opening its collapse', async () => {
    setupAdmin([rule(1, {
      load_balance_strategy: 'failover',
      upload_limit_mbps: 20,
      download_limit_mbps: 80,
      max_connections: 77,
      auto_restart_minutes: 120,
    })]);
    const dialog = await openRuleEditor();
    fireEvent.click(within(dialog).getByRole('tab', { name: 'tabForward' }));
    expect(within(dialog).getByText('lbFailover')).toBeInTheDocument();
    expect(within(dialog).getByText('ruleForwardAdvancedSettings · ruleAdvancedConfiguredCount')).toBeInTheDocument();
    expect(within(dialog).getByText('rateLimits · maxConnections · autoRestart')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'editRule' })).toBeNull());
    expect(mockPut).not.toHaveBeenCalled();

    const reopened = await openExistingRuleEditor();
    fireEvent.change(within(reopened).getByLabelText('name'), { target: { value: 'advanced-preserved' } });
    fireEvent.click(within(reopened).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/rules/1', { name: 'advanced-preserved' }));
  });

  it('keeps collapse values stable and changes only one requested advanced setting pair', async () => {
    setupAdmin([rule(1, {
      upload_limit_mbps: 20,
      download_limit_mbps: 80,
      max_connections: 77,
      auto_restart_minutes: 120,
    })]);
    const dialog = await openRuleEditor();
    fireEvent.click(within(dialog).getByRole('tab', { name: 'tabForward' }));
    const collapse = within(dialog).getByText(/ruleForwardAdvancedSettings/);
    fireEvent.click(collapse);
    expect(within(dialog).getByLabelText('maxConnections')).toHaveValue('77');
    expect(within(dialog).getByLabelText('autoRestart')).toHaveValue('120');
    fireEvent.click(collapse);
    fireEvent.click(collapse);
    expect(within(dialog).getByLabelText('maxConnections')).toHaveValue('77');
    expect(within(dialog).getByLabelText('autoRestart')).toHaveValue('120');

    fireEvent.change(within(dialog).getByLabelText('maxConnections'), { target: { value: '88' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/rules/1', {
      max_connections: 88,
      auto_restart_minutes: 120,
    }));
    const payload = mockPut.mock.calls.at(-1)?.[1] as Record<string, unknown>;
    expect(payload).not.toHaveProperty('upload_limit_mbps');
    expect(payload).not.toHaveProperty('download_limit_mbps');
    expect(payload).not.toHaveProperty('load_balance_strategy');
  });

  it('merges selection across group tables and exposes a cancellable batch bar', async () => {
    setupAdmin([rule(1), rule(2, { device_group_in: 8 })], [group(7, 'tokyo'), group(8, 'osaka')]);
    render(<Rules />);
    const tokyo = await screen.findByTestId('rules-group-7');
    const osaka = screen.getByTestId('rules-group-8');
    fireEvent.click(within(tokyo).getAllByRole('checkbox')[1]);
    fireEvent.click(within(osaka).getAllByRole('checkbox')[1]);
    const batchbar = screen.getByTestId('rules-batchbar');
    expect(batchbar).toHaveAttribute('data-selected-count', '2');
    fireEvent.click(within(batchbar).getByRole('button', { name: 'cancelSelection' }));
    expect(screen.queryByTestId('rules-batchbar')).toBeNull();
  });

  it('clears hidden selections when search criteria change', async () => {
    render(<Rules />);
    const section = await screen.findByTestId('rules-group-7');
    fireEvent.click(within(section).getAllByRole('checkbox')[1]);
    expect(screen.getByTestId('rules-batchbar')).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('searchRulePlaceholder'), { target: { value: 'missing' } });
    expect(screen.queryByTestId('rules-batchbar')).toBeNull();
  });

  it('paginates globally before grouping and keeps full filtered group totals', async () => {
    setupAdmin(Array.from({ length: 25 }, (_, index) => rule(index + 1)));
    render(<Rules />);
    const section = await screen.findByTestId('rules-group-7');
    expect(within(section).getByText('ruleCount')).toBeInTheDocument();
    expect(document.querySelectorAll('.rp-rules-table .ant-table-tbody .ant-table-row')).toHaveLength(20);
    expect(screen.getByTestId('rules-pagination')).toBeInTheDocument();
    fireEvent.click(screen.getByTitle('2'));
    expect(await screen.findByText('rule-25')).toBeInTheDocument();
    expect(document.querySelectorAll('.rp-rules-table .ant-table-tbody .ant-table-row')).toHaveLength(5);
  });
});
