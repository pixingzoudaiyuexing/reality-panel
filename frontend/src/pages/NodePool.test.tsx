import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

const { mockGet, mockPatch, mockPost } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPatch: vi.fn(), mockPost: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet, patch: mockPatch, post: mockPost } }));

import NodePool from './NodePool';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

beforeEach(() => {
  mockGet.mockReset(); mockPatch.mockReset(); mockPost.mockReset();
  mockGet.mockResolvedValue(ok([{ identity_group_id: 10, node_id: 'NODE_A', display_name: 'Relay A',
    public_ipv4: '203.0.113.5', public_ipv6: null, online: false, node_version: '1.1.26',
    last_seen: '2026-09-27T00:00:00Z', memberships: [{ group_id: 20, group_name: 'Japan', native: false }] }]));
  mockPatch.mockResolvedValue(ok(null));
  mockPost.mockResolvedValue(ok(null));
});

describe('NodePool', () => {
  it('shows concrete node status and edits display name as metadata', async () => {
    render(<NodePool />);
    expect(await screen.findByText('Relay A')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.5')).toBeInTheDocument();
    expect(screen.getByText('nodeHealth_UNKNOWN')).toBeInTheDocument();
    expect(screen.getByText('Japan')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /edit/ }));
    fireEvent.change(screen.getByLabelText('poolNodeName'), { target: { value: 'Tokyo relay' } });
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(mockPatch).toHaveBeenCalledWith('/admin/node-pool/nodes/10/NODE_A', { display_name: 'Tokyo relay' }));
  });

  it('blocks retirement while referenced, then requires exact ID and online confirmation', async () => {
    const preview = { identity_group_id: 10, node_id: 'NODE_A', display_name: 'Relay A',
      public_ipv4: '203.0.113.5', public_ipv6: null, last_seen: '2026-09-27T00:00:00Z',
      online: true, control_connected: true, credential_active: true,
      memberships: [{ group_id: 20, group_name: 'Japan', native: false }],
      blockers: ['REUSE_MEMBERSHIP:20'], warnings: ['NODE_CURRENTLY_ONLINE'], retirement_version: 0 };
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/node-pool/nodes/10/NODE_A/retirement-preview') return Promise.resolve(ok(preview));
      if (url === '/admin/node-pool/retired') return Promise.resolve(ok([]));
      return Promise.resolve(ok([{ identity_group_id: 10, node_id: 'NODE_A', display_name: 'Relay A',
        public_ipv4: '203.0.113.5', public_ipv6: null, online: true, node_version: '1.3.0',
        last_seen: preview.last_seen, memberships: preview.memberships }]));
    });
    render(<NodePool />);
    fireEvent.click(await screen.findByRole('button', { name: 'poolRetire' }));
    expect(await screen.findByText('poolRetireBlocked')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('poolRetireReason'), { target: { value: 'retired host' } });
    fireEvent.change(screen.getByLabelText('poolRetireConfirmId'), { target: { value: 'NODE_A' } });
    fireEvent.click(screen.getByText('poolRetireOnlineConfirm'));
    expect(screen.getByRole('button', { name: 'OK' })).toBeDisabled();
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('restores only after explicit exact-ID confirmation', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/node-pool/nodes') return Promise.resolve(ok([]));
      if (url === '/admin/node-pool/retired') return Promise.resolve(ok([{
        identity_group_id: 10, node_id: 'NODE_A', display_name: 'Relay A', retirement_state: 'RETIRED',
        retired_at: '2026-09-27', retired_by: 1, retirement_reason: 'retired host', retirement_version: 1,
      }]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    render(<NodePool />);
    fireEvent.click(screen.getByRole('tab', { name: 'poolRetired' }));
    await screen.findByText('retired host');
    fireEvent.click(screen.getByRole('button', { name: /poolRestore/ }));
    expect(screen.getByRole('button', { name: 'OK' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('poolRetireConfirmId'), { target: { value: 'NODE_A' } });
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/node-pool/nodes/10/NODE_A/restore',
      { expected_version: 1, confirm_node_id: 'NODE_A' }));
  });
});
