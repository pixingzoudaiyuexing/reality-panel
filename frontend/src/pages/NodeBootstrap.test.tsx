import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

const { mockGet, mockPost } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPost: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet, post: mockPost } }));

import NodeBootstrap from './NodeBootstrap';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const group = { id: 7, name: 'relay-group', group_type: 'in', uid: 1, connect_host: '', port_range: '', rate: 1, hidden: false, fallback_group: null, config: '', created_at: '' };
const created = (state = 'PENDING') => ({
  enrollment: { id: '11111111-1111-1111-1111-111111111111', group_id: 7, state, expires_at: '2030-01-01T00:00:00Z' },
  enrollment_secret: 'one-time-enrollment-secret',
  launcher_command: "curl --proto '=http,https' 'https://panel.test/api/v1/node-enrollments/manual-bootstrap-launcher.sh' | bash -s -- --panel-url 'https://panel.test' --enrollment-id '11111111-1111-1111-1111-111111111111'",
});

function renderPage(path = '/node-bootstrap?group_id=7') {
  return render(<MemoryRouter initialEntries={[path]}><NodeBootstrap /></MemoryRouter>);
}

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockGet.mockImplementation((url: string) => {
    if (url === '/groups') return Promise.resolve(ok([group]));
    return Promise.resolve(ok(null));
  });
});

describe('Node Bootstrap deployment modes', () => {
  it('keeps the SSH form available with the Device Group preselected', async () => {
    renderPage();
    await waitFor(() => expect(screen.getAllByText('relay-group').length).toBeGreaterThan(0));
    expect(screen.getByLabelText('nodeBootstrapHost')).toBeInTheDocument();
    expect(screen.getByText('nodeBootstrapSshRecommended')).toBeInTheDocument();
  });

  it('creates a Manual Bootstrap enrollment without putting the secret in its launcher command', async () => {
    const user = userEvent.setup();
    mockPost.mockResolvedValue(ok(created()));
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'manualBootstrapTab' }));
    await user.click(screen.getByRole('button', { name: /manualBootstrapCreate/ }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/node-enrollments', { group_id: 7, profile: 'reality_camouflage' }));
    expect(screen.getByDisplayValue('one-time-enrollment-secret')).toBeInTheDocument();
    const command = screen.getByDisplayValue(/manual-bootstrap-launcher\.sh/);
    expect(command).not.toHaveValue(expect.stringContaining('one-time-enrollment-secret'));
    expect(command).not.toHaveValue(expect.stringContaining('group-token'));
  });

  it('removes the only rendered secret after acknowledgement and status refresh cannot restore it', async () => {
    const user = userEvent.setup();
    mockPost.mockResolvedValue(ok(created('LOCAL_COMMITTED')));
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'manualBootstrapTab' }));
    await user.click(screen.getByRole('button', { name: /manualBootstrapCreate/ }));
    await screen.findByText('manualBootstrapLocalCommitted');
    await user.click(screen.getByRole('button', { name: 'manualBootstrapSecretAcknowledged' }));
    expect(screen.queryByDisplayValue('one-time-enrollment-secret')).toBeNull();
    expect(screen.getByText('manualBootstrapStateLOCAL_COMMITTED')).toBeInTheDocument();
  });

  it('hides the one-time secret when leaving Manual Bootstrap and renders terminal enrollment status', async () => {
    const user = userEvent.setup();
    mockPost.mockResolvedValue(ok(created('EXPIRED')));
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'manualBootstrapTab' }));
    await user.click(screen.getByRole('button', { name: /manualBootstrapCreate/ }));
    await screen.findByDisplayValue('one-time-enrollment-secret');
    await user.click(screen.getByRole('tab', { name: 'nodeBootstrapSshTab' }));
    expect(screen.queryByDisplayValue('one-time-enrollment-secret')).toBeNull();
    await user.click(screen.getByRole('tab', { name: 'manualBootstrapTab' }));
    expect(screen.getByText('manualBootstrapStateEXPIRED')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('one-time-enrollment-secret')).toBeNull();
  });
});
