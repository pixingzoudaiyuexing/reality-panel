import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';

const { mockGet, mockPatch, mockDelete } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPatch: vi.fn(), mockDelete: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet, patch: mockPatch, delete: mockDelete } }));

import NodePool from './NodePool';
import { message, Modal } from 'antd';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

// AntD static roots are outside RTL's rendered root. Drain them before jsdom teardown.
afterEach(async () => {
  await act(async () => {
    Modal.destroyAll();
    message.destroy();
  });
  await waitFor(() => {
    expect(document.querySelector('.ant-modal-confirm')).toBeNull();
    expect(document.querySelector('.ant-message-notice')).toBeNull();
  });
});

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
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
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
    expect(await screen.findByText('poolDeleted')).toBeInTheDocument();
    await waitFor(() => expect(document.querySelector('.ant-modal-confirm')).toBeNull());
  });
});


it('offers Panel-local Delete for historical nodes without a credential or runtime', async () => {
  mockGet.mockResolvedValue(ok([{ identity_group_id: 4, node_id: 'LEGACY', pool_native: false, display_name: 'Old Node',
    online: false, memberships: [], node_version: null, last_seen: null }]));
  render(<NodePool />);
  expect(await screen.findByText('Old Node')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'poolDelete' }));
  expect(await screen.findByText('poolDeleteImpact')).toBeInTheDocument();
  expect(mockDelete).not.toHaveBeenCalled();
  fireEvent.click(screen.getAllByRole('button', { name: 'poolDelete' }).at(-1)!);
  await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/admin/node-pool/nodes/4/LEGACY'));
  expect(await screen.findByText('poolDeleted')).toBeInTheDocument();
  await waitFor(() => expect(document.querySelector('.ant-modal-confirm')).toBeNull());
});
