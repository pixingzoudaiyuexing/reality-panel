import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { DeviceGroup, PoolNode } from '../../api/types';

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(), mockPost: vi.fn(),
}));
vi.mock('../../api/client', () => ({ default: { get: mockGet, post: mockPost } }));

import { GroupPoolPicker } from './GroupPoolPicker';
import { poolNodeName } from './poolNodeName';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const group = { id: 20, name: 'Japan', group_type: 'in' } as DeviceGroup;
const node = (over: Partial<PoolNode> = {}): PoolNode => ({
  identity_group_id: 10, node_id: 'NODE_LONG_IDENTIFIER', pool_native: true, display_name: '',
  public_ipv4: '203.0.113.10', public_ipv6: '2001:db8::10', online: false,
  node_version: '1.1.26', last_seen: null, credential_ready: true,
  credential_active: true, safe_to_add: true, migration_incomplete: false,
  recovery_available: false, runtime_verified: false,
  migration_required: false, auth_reload_supported: true, memberships: [], ...over,
});

beforeEach(() => {
  mockGet.mockReset(); mockPost.mockReset();
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

  it('only offers Pool-native nodes, even when an older node has an active credential', async () => {
    mockGet.mockResolvedValue(ok([node(), node({ node_id: 'OLD_NODE', display_name: 'Older relay', pool_native: false })]));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    fireEvent.mouseDown(screen.getByRole('combobox'));
    expect(await screen.findByText('203.0.113.10 · 203.0.113.10 · offline')).toBeInTheDocument();
    expect(screen.queryByText(/Older relay/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /poolStartMigration/ })).not.toBeInTheDocument();
  });

  it('does not offer legacy migration for a pool-native node with unavailable credential', async () => {
    mockGet.mockResolvedValue(ok([node({ credential_ready: false, credential_active: false, safe_to_add: false, migration_required: false })]));
    render(<GroupPoolPicker group={group} onClose={vi.fn()} onChanged={vi.fn()} />);
    await chooseNode();
    expect(screen.getByText('poolCredentialUnavailable')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'poolStartMigration' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /nodeReuseCheck/ })).toBeDisabled();
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
