import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

const { mockGet, refreshCurrentUser } = vi.hoisted(() => ({
  mockGet: vi.fn().mockResolvedValue({ code: 0, message: 'ok', data: [] }),
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

import Rules, { RULE_SELECTION_COLUMN_WIDTH, RULE_TABLE_SCROLL_X } from './Rules';

describe('Rules table practical layout', () => {
  it('keeps page actions in the header and search/filter in a separate toolbar', async () => {
    render(<Rules />);

    const header = screen.getByText('forwardRules').closest('.rp-page-header');
    const toolbar = await screen.findByTestId('rules-toolbar');
    expect(header).not.toBeNull();
    expect(header).toContainElement(screen.getByRole('button', { name: /refresh/ }));
    expect(header).toContainElement(screen.getByRole('button', { name: /exportImport/ }));
    expect(header).toContainElement(screen.getByRole('button', { name: /addRule/ }));
    expect(toolbar).toContainElement(screen.getByPlaceholderText('searchRulePlaceholder'));
    expect(toolbar).toContainElement(screen.getByRole('combobox'));
    expect(header).not.toContainElement(screen.getByPlaceholderText('searchRulePlaceholder'));
  });

  it('keeps the action column present and fixed to the right', async () => {
    render(<Rules />);

    const actionHeader = await screen.findByRole('columnheader', { name: 'action' });
    expect(actionHeader).toHaveClass('ant-table-cell-fix-end');
  });

  it('uses a stable wide table width instead of compressing columns', () => {
    expect(RULE_SELECTION_COLUMN_WIDTH).toBe(48);
    expect(RULE_TABLE_SCROLL_X).toBe(1950);
    expect(RULE_TABLE_SCROLL_X).toBeGreaterThan(1890 + RULE_SELECTION_COLUMN_WIDTH);
  });

  it('keeps long fields single-line and preserves the complete action set', async () => {
    const longName = 'stage31-corrected-remote-reality';
    const longSni = 'very-long-reality-name.example.com';
    const longTarget = '141.11.219.133:55443';
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') return Promise.resolve({ code: 0, message: 'ok', data: [{
        id: 31,
        name: longName,
        uid: 1,
        paused: false,
        listen_port: 443,
        protocol: 'tcp',
        public_transport: 'nginx_sni',
        node_transport: 'nginx_sni',
        device_group_in: 7,
        sni: longSni,
        camouflage_enabled: true,
        target_addr: '141.11.219.133',
        target_port: 55443,
        targets: [{ host: '141.11.219.133', port: 55443, enabled: true }],
        load_balance_strategy: 'first',
        traffic_used: 0,
      }] });
      if (url === '/groups') return Promise.resolve({ code: 0, message: 'ok', data: [{ id: 7, name: 'relay-group', group_type: 'in', connect_host: '203.0.113.10' }] });
      if (url === '/admin/users') return Promise.resolve({ code: 0, message: 'ok', data: [{ id: 1, username: 'admin' }] });
      if (url === '/nodes') return Promise.resolve({ code: 0, message: 'ok', data: [] });
      if (url === '/admin/rules/dns-status') return Promise.resolve({ code: 0, message: 'ok', data: [] });
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    render(<Rules />);

    const name = await screen.findByText(longName);
    expect(name).toHaveClass('rp-rules-ellipsis');
    expect(name).toHaveAttribute('title', longName);
    const sni = screen.getByText(longSni);
    expect(sni).toHaveClass('rp-rules-ellipsis');
    expect(screen.getByText(longTarget)).toHaveClass('rp-rules-ellipsis');

    const row = name.closest('tr');
    expect(row).not.toBeNull();
    const actions = (row as HTMLElement).querySelector('.rp-rules-actions');
    expect(actions).toBeInTheDocument();
    const actionView = within(actions as HTMLElement);
    const buttons = [
      actionView.getByRole('button', { name: /pause/ }),
      actionView.getByRole('button', { name: /edit/ }),
      actionView.getByRole('button', { name: /copy/ }),
      actionView.getByRole('button', { name: /diagnose/ }),
      actionView.getByRole('button', { name: /reapply/ }),
      actionView.getByRole('button', { name: /delete/ }),
    ];
    for (let index = 1; index < buttons.length; index += 1) {
      expect(buttons[index - 1].compareDocumentPosition(buttons[index]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
  });
});
