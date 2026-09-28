import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { DeviceGroup, PoolNode } from '../../api/types';

const { mockGet, mockPost, mockDelete } = vi.hoisted(() => ({
  mockGet: vi.fn(), mockPost: vi.fn(), mockDelete: vi.fn(),
}));
vi.mock('../../api/client', () => ({ default: { get: mockGet, post: mockPost, delete: mockDelete } }));

import { GroupPoolPicker } from './GroupPoolPicker';
import { poolNodeName } from './poolNodeName';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const group = { id: 20, name: 'Japan', group_type: 'in' } as DeviceGroup;
const node = (over: Partial<PoolNode> = {}): PoolNode => ({
  identity_group_id: 10, node_id: 'NODE_LONG_IDENTIFIER', display_name: '',
  public_ipv4: '203.0.113.10', public_ipv6: '2001:db8::10', online: false,
  node_version: '1.1.26', last_seen: null, credential_ready: true,
  credential_active: true, safe_to_add: true, migration_incomplete: false,
  recovery_available: false, runtime_verified: false,
  migration_required: false, auth_reload_supported: true, memberships: [], ...over,
});

beforeEach(() => {
  mockGet.mockReset(); mockPost.mockReset(); mockDelete.mockReset();
  mockGet.mockResolvedValue(ok([node(), node({ node_id: 'ADDED', display_name: 'Existing',
    public_ipv4: '198.51.100.20', public_ipv6: null,
    memberships: [{ group_id: 20, group_name: 'Japan', native: false }] })]));
});

async function chooseNode() {
  fireEvent.mouseDown(screen.getByRole('combobox'));
  const option = await screen.findByText('203.0.113.10 · 203.0.113.10 · offline');
  fireEvent.click(option);
}

describe('GroupPoolPicker', () => {
  it('uses name, IPv4, IPv6 then short ID fallback', () => {
    expect(poolNodeName(node({ display_name: 'Relay A' }))).toBe('Relay A');
    expect(poolNodeName(node())).toBe('203.0.113.10');
    expect(poolNodeName(node({ public_ipv4: null }))).toBe('2001:db8::10');
    expect(poolNodeName(node({ public_ipv4: null, public_ipv6: null }))).toBe('NODE_LONG_ID');
  });

  it('keeps already-added and offline nodes visible, searchable and correctly disabled', async () => {
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    fireEvent.mouseDown(screen.getByRole('combobox'));
    const already = await screen.findByText(/Existing.*poolAlreadyMember/);
    expect(already.closest('.ant-select-item-option')).toHaveClass('ant-select-item-option-disabled');
    expect(await screen.findByText('203.0.113.10 · 203.0.113.10 · offline')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '2001:db8::10' } });
    await waitFor(() => expect(screen.queryByText(/Existing.*poolAlreadyMember/)).not.toBeInTheDocument());
    expect(screen.getByText('203.0.113.10 · 203.0.113.10 · offline')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'NODE_LONG_IDENTIFIER' } });
    expect(screen.getByText('203.0.113.10 · 203.0.113.10 · offline')).toBeInTheDocument();
  });

  it('shows legacy upgrade gate in the add flow and never creates a membership', async () => {
    mockGet.mockResolvedValue(ok([node({ credential_ready: false, credential_active: false, safe_to_add: false, migration_required: true, auth_reload_supported: false })]));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    expect(screen.getByText('poolUpgradeRequired')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'poolConvergeNode' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'poolStartMigration' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /nodeReuseCheck/ })).toBeDisabled();
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('shows an existing migration authorization without creating another', async () => {
    mockGet.mockResolvedValue(ok([node({ credential_ready: false, credential_active: false, safe_to_add: false, migration_required: true,
      migration_pending: true, migration_claim_id: 'claim-a' })]));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    expect(screen.getByText('poolMigrationExistingPending')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'poolStartMigration' })).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('does not offer legacy migration for a pool-native node with unavailable credential', async () => {
    mockGet.mockResolvedValue(ok([node({ credential_ready: false, credential_active: false, safe_to_add: false, migration_required: false })]));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    expect(screen.getByText('poolCredentialUnavailable')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'poolStartMigration' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /nodeReuseCheck/ })).toBeDisabled();
  });

  it('keeps active-but-incomplete migration recoverable without enabling Add', async () => {
    mockGet.mockResolvedValue(ok([node({ credential_ready: false, credential_active: true,
      safe_to_add: false, migration_required: true, migration_incomplete: true,
      recovery_available: true, migration_pending: true, migration_claim_id: 'claim-a' })]));
    mockPost.mockResolvedValue(ok({ claim: { claim_id: 'claim-a' }, claim_secret: null,
      command: 'python3 migrate.py --claim-id claim-a', recovery: true }));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    expect(screen.getByText('poolMigrationIncomplete')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /nodeReuseCheck/ })).toBeDisabled();
    fireEvent.click(screen.getByText('poolAdvancedRecovery'));
    fireEvent.click(screen.getByRole('button', { name: 'poolContinueMigration' }));
    expect(await screen.findByText('python3 migrate.py --claim-id claim-a')).toBeInTheDocument();
    expect(screen.queryByLabelText('poolMigrationSecret')).not.toBeInTheDocument();
    expect(mockPost).toHaveBeenCalledWith('/admin/node-pool/nodes/10/NODE_LONG_IDENTIFIER/migration');
    expect(mockPost).toHaveBeenCalledTimes(1);
  });

  it('starts automatic identity convergence without exposing a migration command or adding membership', async () => {
    mockGet.mockResolvedValue(ok([node({ credential_ready: false, credential_active: false,
      safe_to_add: false, migration_required: true, auth_reload_supported: false })]));
    mockPost.mockResolvedValue(ok({ id: 'operation-1', group_id: 10, node_id: 'NODE_LONG_IDENTIFIER',
      action: 'upgrade', status: 'INSTALLING', convergence_phase: 'UPGRADING' }));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    fireEvent.click(screen.getByRole('button', { name: 'poolConvergeNode' }));
    expect(await screen.findByText('poolConvergence_UPGRADING')).toBeInTheDocument();
    expect(mockPost).toHaveBeenCalledWith('/admin/node-pool/nodes/10/NODE_LONG_IDENTIFIER/identity-convergence', {});
    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/migrate\.py/)).not.toBeInTheDocument();
  });

  it('does not add a node after conflicting prospective preflight', async () => {
    mockPost.mockResolvedValue(ok({ sources: [], conflicts: [{ kind: 'TCP_PORT_COLLISION' }],
      known_runtime_prerequisites_satisfied: false }));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    fireEvent.click(screen.getByRole('button', { name: /nodeReuseCheck/ }));
    expect(await screen.findByText('nodeReuseCheckBlocked')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'addNode' })).toBeDisabled();
    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
  });

  it('persists only after safe preflight and displays server sync state', async () => {
    mockPost.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/preview')
      ? { sources: [], conflicts: [], known_runtime_prerequisites_satisfied: true }
      : { outcome: 'CREATED' })));
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/runtime-status')
      ? { sync_state: 'OFFLINE', expected_revision: 3 }
      : [node()])));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    fireEvent.click(screen.getByRole('button', { name: /nodeReuseCheck/ }));
    expect(await screen.findByText('nodeReuseCheckPassed')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'addNode' }));
    expect(await screen.findByText('nodeReuseState_OFFLINE')).toBeInTheDocument();
    expect(mockPost).toHaveBeenCalledWith('/admin/groups/20/nodes', { identity_group_id: 10, node_id: 'NODE_LONG_IDENTIFIER' });
  });
});
