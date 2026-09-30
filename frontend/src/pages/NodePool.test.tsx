import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

const { mockGet, mockPatch, mockDelete } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPatch: vi.fn(), mockDelete: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet, patch: mockPatch, delete: mockDelete } }));

import NodePool from './NodePool';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

beforeEach(() => {
  mockGet.mockReset(); mockPatch.mockReset(); mockDelete.mockReset();
  mockGet.mockResolvedValue(ok([{ identity_group_id: 10, node_id: 'NODE_A', pool_native: true, display_name: 'Relay A',
    public_ipv4: '203.0.113.5', public_ipv6: null, online: false, node_version: '1.1.26',
    last_seen: '2026-09-27T00:00:00Z', memberships: [
      { group_id: 20, group_name: 'Japan', native: false },
      { group_id: 30, group_name: 'Singapore', native: false },
    ] }]));
  mockPatch.mockResolvedValue(ok(null));
  mockDelete.mockResolvedValue(ok({ warnings: [] }));
});

describe('NodePool', () => {
  it('shows concrete node status and edits display name as metadata', async () => {
    render(<NodePool />);
    expect(await screen.findByText('Relay A')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.5')).toBeInTheDocument();
    expect(screen.getByText('offline')).toBeInTheDocument();
    expect(screen.getByText('Japan')).toBeInTheDocument();
    expect(screen.getByText('Singapore')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /edit/ }));
    fireEvent.change(screen.getByLabelText('poolNodeName'), { target: { value: 'Tokyo relay' } });
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(mockPatch).toHaveBeenCalledWith('/admin/node-pool/nodes/10/NODE_A', { display_name: 'Tokyo relay' }));
  });

  it('confirms offline deletion before calling the actual Pool retirement endpoint', async () => {
    render(<NodePool />);
    expect(await screen.findByText('Relay A')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'poolUninstall' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'poolDelete' }));
    expect(await screen.findByText('poolDeleteImpact')).toBeInTheDocument();
    expect(mockDelete).not.toHaveBeenCalled();
    fireEvent.click(screen.getAllByRole('button', { name: 'poolDelete' }).at(-1)!);
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/admin/node-pool/nodes/10/NODE_A'));
  });
});
