import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { Modal } from 'antd';

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
  expect(screen.queryAllByRole('dialog', { hidden: true })).toHaveLength(0);
  mockGet.mockReset();
  mockPost.mockReset();
  mockGet.mockImplementation((url: string) => {
    if (url === '/groups') return Promise.resolve(ok([group]));
    return Promise.resolve(ok(null));
  });
});

afterEach(async () => {
  // Static confirmations own a separate React root, outside render()/cleanup().
  await act(async () => { Modal.destroyAll(); });
  cleanup();
  await waitFor(() => expect(screen.queryAllByRole('dialog', { hidden: true })).toHaveLength(0));
});

describe('Node Bootstrap deployment modes', () => {
  it('deploys into the pool without requiring a business group', async () => {
    renderPage();
    expect(screen.queryByText('relay-group')).not.toBeInTheDocument();
    expect(screen.getByLabelText('nodeBootstrapHost 1')).toBeInTheDocument();
    expect(screen.getByText('nodeBootstrapSshRecommended')).toBeInTheDocument();
  });

  it('tests dynamic rows concurrently and deploys every passed row without another confirmation', async () => {
    const user = userEvent.setup();
    mockPost.mockImplementation((url: string, body: { host: string }) => {
      if (url.endsWith('/fingerprint')) return Promise.resolve(ok({ fingerprint: `SHA256:${body.host}`, os: 'Debian', architecture: 'x86_64' }));
      if (url === '/admin/node-deployments') return Promise.resolve(ok({ id: `task-${body.host}`, group_id: 7, host: body.host, stage: 'PENDING', status: 'PENDING', message: 'queued', profile: 'reality_camouflage' }));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderPage();
    expect(screen.queryByLabelText('nodeBootstrapGroup 1')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /nodeBootstrapAddServer/ }));
    await user.type(screen.getByLabelText('nodeBootstrapHost 1'), 'node-a');
    await user.type(screen.getByLabelText('nodeBootstrapPassword 1'), 'secret-a');
    await user.type(screen.getByLabelText('nodeBootstrapHost 2'), 'node-b');
    await user.type(screen.getByLabelText('nodeBootstrapPassword 2'), 'secret-b');
    await user.click(screen.getByRole('button', { name: /nodeBootstrapTestConnection/ }));
    await waitFor(() => expect(screen.getAllByText('nodeBootstrapRowPASSED')).toHaveLength(2));
    await user.click(screen.getByRole('button', { name: /nodeBootstrapDeploy/ }));
    await waitFor(() => expect(mockPost.mock.calls.filter(([url]) => url === '/admin/node-deployments')).toHaveLength(2));
    expect(screen.getByRole('button', { name: /nodeBootstrapAddServer/ })).toBeDisabled();
    expect(screen.getByLabelText('nodeBootstrapHost 1')).toBeDisabled();
    expect(mockPost).toHaveBeenCalledWith('/admin/node-deployments', expect.objectContaining({ host: 'node-a', confirmed_fingerprint: 'SHA256:node-a' }));
    expect(mockPost).toHaveBeenCalledWith('/admin/node-deployments', expect.objectContaining({ host: 'node-b', confirmed_fingerprint: 'SHA256:node-b' }));
    expect(mockPost).toHaveBeenCalledWith('/admin/node-deployments', expect.objectContaining({ lite_mode: false }));
  });

  it('sends lite_mode only for SSH deployments selected as Lite', async () => {
    const user = userEvent.setup();
    mockPost.mockImplementation((url: string, body: { host: string }) => {
      if (url.endsWith('/fingerprint')) return Promise.resolve(ok({ fingerprint: `SHA256:${body.host}`, os: 'Debian', architecture: 'x86_64' }));
      if (url === '/admin/node-deployments') return Promise.resolve(ok({ id: 'task-lite', group_id: 7, host: body.host, stage: 'PENDING', status: 'PENDING', message: 'queued', profile: 'reality_camouflage', lite_mode: true }));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderPage();
    expect(screen.queryByLabelText('nodeBootstrapGroup 1')).not.toBeInTheDocument();
    await user.click(screen.getByText('nodeBootstrapInstallLite'));
    await user.type(screen.getByLabelText('nodeBootstrapHost 1'), 'node-lite');
    await user.type(screen.getByLabelText('nodeBootstrapPassword 1'), 'secret');
    await user.click(screen.getByRole('button', { name: /nodeBootstrapTestConnection/ }));
    await screen.findByText('nodeBootstrapRowPASSED');
    await user.click(screen.getByRole('button', { name: /nodeBootstrapDeploy/ }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/node-deployments', expect.objectContaining({
      host: 'node-lite',
      lite_mode: true,
      profile: 'reality_camouflage',
    })));
  });

  it('creates a Manual Bootstrap enrollment without putting the secret in its launcher command', async () => {
    const user = userEvent.setup();
    mockPost.mockResolvedValue(ok(created()));
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'manualBootstrapTab' }));
    await user.click(screen.getByRole('button', { name: /manualBootstrapCreate/ }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/node-enrollments', { profile: 'reality_camouflage' }));
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


const managed = { classification: 'MANAGED_EXISTING_NODE', old_node_id: 'old-node', version: '1.4.4', profile: 'standard', service_active: true, panel_present: true, online: true, credential_active: true, group_count: 2, carrier_reference_count: 3, confirmation: 'snapshot-proof', reason: null };
async function inspectExisting(existing = managed) {
  const user = userEvent.setup();
  mockPost.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/fingerprint') ? { fingerprint: 'SHA256:node-a', os: 'Debian', architecture: 'amd64', existing } : { id: 'task', status: 'PENDING', stage: 'PENDING', host: 'node-a' })));
  renderPage();
  await user.type(screen.getByLabelText('nodeBootstrapHost 1'), 'node-a');
  await user.type(screen.getByLabelText('nodeBootstrapPassword 1'), 'test-only-password');
  await user.click(screen.getByText('nodeBootstrapTestConnection'));
  await screen.findByText('overwriteExistingTitle');
  return user;
}
describe('Destructive fresh reinstall', () => {
  it('enables deploy after SSH success and cancellation leaves the old installation untouched', async () => {
    const user = await inspectExisting();
    expect(screen.getByText('nodeBootstrapDeploy').closest('button')).toBeEnabled();
    await user.click(screen.getByText('nodeBootstrapDeploy'));
    const dialog = await screen.findByRole('dialog');
    expect(screen.getAllByText('freshResetConfirm').length).toBeGreaterThan(0);
    await user.click(within(dialog).getByRole('button', { name: 'cancel' }));
    await waitFor(() => expect(dialog).not.toBeInTheDocument());
    expect(mockPost.mock.calls.filter(([url]) => url === '/admin/node-deployments')).toHaveLength(0);
    expect(screen.getByText('nodeBootstrapDeploy').closest('button')).toBeEnabled();
  });
  it.each(['MANAGED_EXISTING_NODE', 'STALE_INACTIVE_RESIDUE', 'AMBIGUOUS_STATE'])('installs %s with only the confirmed SSH fingerprint', async (classification) => {
    const user = await inspectExisting({ ...managed, classification, reason: 'old identity / credential / Panel mismatch' });
    expect(screen.getByText('freshResetInconsistent')).toBeInTheDocument();
    expect(screen.getByText('nodeBootstrapDeploy').closest('button')).toBeEnabled();
    await user.click(screen.getByText('nodeBootstrapDeploy'));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'overwriteConfirm' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/node-deployments', expect.objectContaining({ confirmed_fingerprint: 'SHA256:node-a' })));
    const payload = mockPost.mock.calls.find(([url]) => url === '/admin/node-deployments')![1];
    expect(payload).not.toHaveProperty('overwrite_node_id');
    expect(payload).not.toHaveProperty('existing_confirmation');
  });
  it('shows the new candidate and hides obsolete diagnostic state once deployment starts', async () => {
    const user = await inspectExisting();
    await user.click(screen.getByText('nodeBootstrapDeploy'));
    const dialog = await screen.findByRole('dialog');
    const newId = '22222222-2222-4222-8222-222222222222';
    mockPost.mockResolvedValueOnce(ok({ id: 'task', status: 'SUCCESS', stage: 'SUCCESS', host: 'node-a', node_id: newId, candidate_node_id: newId, message: 'completed' }));
    await user.click(within(dialog).getByRole('button', { name: 'overwriteConfirm' }));
    await screen.findByText(`overwriteNewNode: ${newId}`);
    expect(screen.queryByText('overwriteExistingTitle')).not.toBeInTheDocument();
  });
});
